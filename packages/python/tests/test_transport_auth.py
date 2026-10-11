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

    def test_verified_subject_carries_caller_key_id(self) -> None:
        # a419e02: the verified subject carries the caller's CHP key_id (from the pinned pubkey),
        # which is what enables the activation-effect gate's key-based checks over HTTP.
        status, body = self._invoke(self._token())
        self.assertEqual(status, 200)
        corr = body["correlation"]["correlation_id"]
        subj = self.host.replay(corr)[0].get("subject") or {}
        self.assertEqual(subj.get("key_id"), self.key.key_id)
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


class ActivationOverHttpTests(__import__("unittest").TestCase):
    """a419e02 capstone: a token-authed caller's verified key_id now flows to the activation gate, so
    a privileged activation effect can be authorized over HTTP (and self-approval still denied)."""

    PLAN = "sha256:" + "e" * 64
    AUD = "host-b:acme"

    def setUp(self) -> None:
        self.host = LocalCapabilityHost("host-b", store=SQLiteEvidenceStore(":memory:"))
        self.calls = {"n": 0}

        async def handler(_ctx, payload):
            self.calls["n"] += 1
            return {"ok": True}

        self.host.register(CapabilityDescriptor(id="deploy.cap", version="1.0.0", description="."), handler)
        self._tmp = __import__("tempfile").TemporaryDirectory()
        self.caller = signing.generate_keypair(Path(self._tmp.name) / "caller")
        self.approver = signing.generate_keypair(Path(self._tmp.name) / "approver")
        os.environ["CHP_HOST_TOKEN_KEYS"] = f"alice:{self.caller.public_key_b64}"
        os.environ["CHP_HOST_APPROVER_KEYS"] = self.approver.key_id
        os.environ["CHP_HOST_ACTIVATION_AUDIENCE"] = self.AUD
        self.srv = CapabilityHostHTTPServer(("127.0.0.1", 0), self.host)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self._tmp.cleanup()
        for v in ("CHP_HOST_TOKEN_KEYS", "CHP_HOST_APPROVER_KEYS", "CHP_HOST_ACTIVATION_AUDIENCE"):
            os.environ.pop(v, None)

    def _token(self):
        now = datetime.now(timezone.utc)
        return signing.build_auth_token(self.caller, sub="alice", aud="host-b",
                                        iat=_iso(now - timedelta(minutes=1)),
                                        exp=_iso(now + timedelta(minutes=5)))

    def _invoke(self, approver_for_grant):
        grant = signing.build_approval_grant(
            approver_for_grant, invocation_id="inv-http", payload_commitment="sha256:" + "f" * 64,
            approval_id="ap-http", valid_until="2099-01-01T00:00:00Z",
            action_digest=self.PLAN, audience=self.AUD, max_attempts=1)
        body = json.dumps({
            "capability_id": "deploy.cap", "payload": {},
            "approval_ref": grant,
            "activation_ref": {"plan_digest": self.PLAN, "effect_kind": "CONNECT",
                               "readiness_eligible": True},
        }).encode()
        req = urllib.request.Request(f"{self.base}/invoke", data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "X-CHP-Token": json.dumps(self._token())})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def test_activation_authorized_over_http(self) -> None:
        # approver (out-of-band) != caller → authorized, effect runs
        resp = self._invoke(self.approver)
        self.assertEqual(resp.get("outcome"), "success")
        self.assertEqual(self.calls["n"], 1)

    def test_self_approval_over_http_denied(self) -> None:
        # the CALLER signs their own grant (approver == caller key) → self-approval → denied
        os.environ["CHP_HOST_APPROVER_KEYS"] = self.caller.key_id  # trust the caller's key as approver
        resp = self._invoke(self.caller)
        self.assertEqual(resp.get("outcome"), "denied")
        self.assertEqual(resp.get("denial", {}).get("code"), "activation_not_authorized")
        self.assertEqual(self.calls["n"], 0)


class OpenModeSubjectSanitizeTests(__import__("unittest").TestCase):
    """a419e02: an unauthenticated / open-mode client MUST NOT be able to self-assert a verified
    identity or signing key_id — the activation gate keys off exactly those, so they are stripped."""

    def setUp(self) -> None:
        for v in ("CHP_HOST_TOKEN_KEYS", "CHP_HOST_API_KEYS", "CHP_HOST_API_KEY"):
            os.environ.pop(v, None)
        self.host = LocalCapabilityHost("open-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"ok": True}

        self.host.register(CapabilityDescriptor(id="c.echo", version="1.0.0", description="."), handler)
        self.srv = CapabilityHostHTTPServer(("127.0.0.1", 0), self.host)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.srv.shutdown()

    def test_unauthenticated_client_cannot_assert_verified_or_key_id(self) -> None:
        body = json.dumps({
            "capability_id": "c.echo", "payload": {},
            "subject": {"id": "mallory", "verified": True, "key_id": "some-approver-key"},
        }).encode()
        req = urllib.request.Request(f"{self.base}/invoke", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
        corr = resp["correlation"]["correlation_id"]
        subj = self.host.replay(corr)[0].get("subject") or {}
        self.assertNotIn("verified", subj)   # self-asserted trust signal stripped
        self.assertNotIn("key_id", subj)      # self-asserted key stripped
        self.assertEqual(subj.get("id"), "mallory")  # id retained, but unverified


if __name__ == "__main__":
    __import__("unittest").main()
