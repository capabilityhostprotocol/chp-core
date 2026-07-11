"""Revocation freshness (chp-v0.2.md §12, proposal 0010): the
chp-revocation-head-v1 digest, its binding into the witnessed head, the
recompute-and-match on receipt, and the dropped-revocation audit."""

from __future__ import annotations

import base64
import json
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core import revocations, signing, witnessing
from chp_core.types import CorrelationContext, InvocationEnvelope


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _iso(datetime.now(timezone.utc))


def _witness_key(offset: int = 200) -> signing.HostKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                           public_key_b64=pub, _private=priv)


class RevocationHeadDigestTests(unittest.TestCase):
    def test_digest_is_deterministic_and_order_independent(self) -> None:
        a = [{"mandate_id": "m1", "principal": {"public_key": "kA"}},
             {"mandate_id": "m2", "principal": {"public_key": "kB"}}]
        ids1 = revocations.revocation_ids(a, [])
        ids2 = revocations.revocation_ids(list(reversed(a)), [])
        self.assertEqual(ids1, ids2)
        self.assertEqual(revocations.compute_revocation_head(ids1),
                         revocations.compute_revocation_head(ids2))

    def test_empty_set_has_a_defined_digest(self) -> None:
        import hashlib
        self.assertEqual(revocations.compute_revocation_head([]),
                         hashlib.sha256(b"").hexdigest())

    def test_adding_a_revocation_moves_the_head(self) -> None:
        base = revocations.compute_revocation_head(
            revocations.revocation_ids([{"mandate_id": "m1", "principal": {"public_key": "k"}}], []))
        more = revocations.compute_revocation_head(
            revocations.revocation_ids(
                [{"mandate_id": "m1", "principal": {"public_key": "k"}},
                 {"mandate_id": "m2", "principal": {"public_key": "k"}}], []))
        self.assertNotEqual(base, more)

    def test_key_revocations_included(self) -> None:
        ids = revocations.revocation_ids([], [{"revoked_key_id": "abc123"}])
        self.assertEqual(ids, ["k\x00abc123"])


class RevocationHeadStatementTests(unittest.TestCase):
    def test_revocation_head_signed_when_present(self) -> None:
        rh = revocations.compute_revocation_head(["m\x00m1\x00k"])
        stmt = signing.build_chain_witness(
            "host-a", 5, "0" * 64, _witness_key(), witness_id="w",
            witnessed_at=_now(), revocation_head=rh)
        self.assertEqual(stmt["revocation_head"], rh)
        self.assertTrue(signing.verify_chain_witness(stmt, expected_host_id="host-a").valid)
        # tampering the revocation_head breaks the signature (it's header-signed)
        stmt["revocation_head"] = "f" * 64
        self.assertFalse(signing.verify_chain_witness(stmt).checks["signature"])

    def test_absent_revocation_head_is_byte_identical_to_pre_0010(self) -> None:
        # A statement built WITHOUT revocation_head has the classic header — no
        # revocation_head key, and its header projection is the 6 base fields.
        stmt = signing.build_chain_witness(
            "host-a", 5, "0" * 64, _witness_key(), witness_id="w", witnessed_at=_now())
        self.assertNotIn("revocation_head", stmt)
        header = signing.chain_witness_header(stmt)
        self.assertEqual(set(header), set(signing._CHAIN_WITNESS_HEADER_FIELDS))


class FreshnessAuditTests(unittest.TestCase):
    def test_dropped_revocation_is_flagged(self) -> None:
        snapshot = ["m\x00m1\x00k", "m\x00m2\x00k"]
        rh = revocations.compute_revocation_head(snapshot)
        receipt = {"statement": {"sequence": 7, "revocation_head": rh},
                   "revocations": snapshot}
        # current set is MISSING m2 → dropped
        audit = revocations.audit_revocation_freshness([receipt], ["m\x00m1\x00k"])
        self.assertEqual(audit["verdict"], "dropped")
        self.assertEqual(audit["dropped"], ["m\x00m2\x00k"])

    def test_fresh_when_current_superset(self) -> None:
        snapshot = ["m\x00m1\x00k"]
        rh = revocations.compute_revocation_head(snapshot)
        receipt = {"statement": {"sequence": 7, "revocation_head": rh}, "revocations": snapshot}
        audit = revocations.audit_revocation_freshness(
            [receipt], ["m\x00m1\x00k", "m\x00m2\x00k"])  # grew, none dropped
        self.assertEqual(audit["verdict"], "fresh")

    def test_doctored_snapshot_is_flagged(self) -> None:
        rh = revocations.compute_revocation_head(["m\x00m1\x00k"])
        receipt = {"statement": {"sequence": 7, "revocation_head": rh},
                   "revocations": ["m\x00m1\x00k", "m\x00forged\x00k"]}  # doesn't match rh
        audit = revocations.audit_revocation_freshness([receipt], [])
        self.assertEqual(audit["verdict"], "snapshot_invalid")

    def test_pre_0010_receipt_ignored(self) -> None:
        receipt = {"statement": {"sequence": 7}, "leaves": {}}  # no revocations
        audit = revocations.audit_revocation_freshness([receipt], [])
        self.assertEqual(audit["verdict"], "fresh")
        self.assertEqual(audit["receipts_checked"], 0)


class WitnessRouteFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = unittest.mock.patch.dict("os.environ", {
            "CHP_WITNESS_DIR": self._mk("w"), "CHP_REVOCATION_DIR": self._mk("r")})
        self._tmp.start()

    def _mk(self, name: str) -> str:
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def tearDown(self) -> None:
        self._tmp.stop()

    def _served(self, host):
        from chp_core.http import create_http_server
        server = create_http_server(host, bind="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def _get(self, url):
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())

    def _post(self, url, body):
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _host(self):
        host = LocalCapabilityHost("fresh-host", store=SQLiteEvidenceStore(":memory:"))

        async def h(_ctx, payload):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="f.cap", version="1.0.0", description="."), h)
        import asyncio
        for c in ("c1", "c2"):
            asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
                capability_id="f.cap", payload={}, correlation=CorrelationContext(correlation_id=c))))
        return host

    def test_head_includes_revocation_head_and_roundtrips(self) -> None:
        host = self._host()
        server, base = self._served(host)
        try:
            head = self._get(f"{base}/head")
            self.assertIn("revocation_head", head)
            self.assertRegex(head["revocation_head"], r"^[0-9a-f]{64}$")
            stmt = signing.build_chain_witness(
                head["host_id"], head["sequence"], head["store_head"], _witness_key(),
                witness_id="peer", witnessed_at=_now(),
                revocation_head=head["revocation_head"])
            accepted = self._post(f"{base}/witness", stmt)
            self.assertTrue(accepted["accepted"])
            # the receipt snapshot was persisted
            rec = witnessing.load_received()
            self.assertEqual(len(rec), 1)
            self.assertIn("revocations", rec[0])
        finally:
            server.shutdown(); server.server_close()

    def test_wrong_revocation_head_refused_409(self) -> None:
        host = self._host()
        server, base = self._served(host)
        try:
            head = self._get(f"{base}/head")
            stmt = signing.build_chain_witness(
                head["host_id"], head["sequence"], head["store_head"], _witness_key(),
                witness_id="peer", witnessed_at=_now(),
                revocation_head="a" * 64)  # a set this host does not hold
            with self.assertRaises(urllib.error.HTTPError) as exc:
                self._post(f"{base}/witness", stmt)
            self.assertEqual(exc.exception.code, 409)
            self.assertEqual(witnessing.load_received(), [])
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
