"""Transport auth — signed bearer tokens (chp-v0.2.md §5, proposal 0027): a caller
mints an ed25519-signed, short-lived, audience-bound token; the host pins sub's
public key and authenticates the verified caller. Bad/expired/wrong-aud → 401."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore, signing
from chp_core.http import CapabilityHostHTTPServer


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TransportAuthTests(__import__("unittest").TestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("host-b", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"ok": True}

        self.host.register(CapabilityDescriptor(id="c.echo", version="1.0.0", description="."), handler)
        self._tmp = __import__("tempfile").TemporaryDirectory()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "k")
        # Pin alice's public key as an authorized token issuer.
        os.environ["CHP_HOST_TOKEN_KEYS"] = f"alice:{self.key.public_key_b64}"
        self.srv = CapabilityHostHTTPServer(("127.0.0.1", 0), self.host)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self._tmp.cleanup()
        os.environ.pop("CHP_HOST_TOKEN_KEYS", None)

    def _token(self, *, sub="alice", aud="host-b", exp_delta=timedelta(minutes=5),
               iat_delta=timedelta(minutes=-1)):
        now = datetime.now(timezone.utc)
        return signing.build_auth_token(self.key, sub=sub, aud=aud,
                                        iat=_iso(now + iat_delta), exp=_iso(now + exp_delta))

    def _invoke(self, token=None):
        body = json.dumps({"capability_id": "c.echo", "payload": {}}).encode()
        req = urllib.request.Request(f"{self.base}/invoke", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token is not None:
            req.add_header("X-CHP-Token", json.dumps(token))
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    def test_valid_token_authenticates_and_binds_subject(self) -> None:
        status, body = self._invoke(self._token())
        self.assertEqual(status, 200)
        self.assertEqual(body.get("outcome"), "success")
        # the evidence subject is the VERIFIED caller
        corr = body["correlation"]["correlation_id"]
        subj = self.host.replay(corr)[0].get("subject") or {}
        self.assertEqual(subj.get("id"), "alice")
        self.assertTrue(subj.get("verified"))

    def test_expired_token_is_401(self) -> None:
        expired = self._token(exp_delta=timedelta(hours=-1), iat_delta=timedelta(hours=-2))
        self.assertEqual(self._invoke(expired)[0], 401)

    def test_wrong_audience_is_401(self) -> None:
        self.assertEqual(self._invoke(self._token(aud="someone-else"))[0], 401)

    def test_unpinned_subject_is_401(self) -> None:
        # a real signature but sub 'mallory' is not pinned
        self.assertEqual(self._invoke(self._token(sub="mallory"))[0], 401)

    def test_tampered_token_is_401(self) -> None:
        t = self._token()
        t["sub"] = "alice"
        t["aud"] = "host-b"
        t["exp"] = _iso(datetime.now(timezone.utc) + timedelta(days=3650))  # extend without re-signing
        self.assertEqual(self._invoke(t)[0], 401)

    def test_no_token_is_401_when_tokens_required(self) -> None:
        self.assertEqual(self._invoke(None)[0], 401)


if __name__ == "__main__":
    __import__("unittest").main()
