"""Mandate revocation (chp-v0.2.md §10 Revocation, proposal 0007): the
statement round-trip, the issuer-only rule (forgery inert), sidecar
persistence, and the gate-5 denial."""

from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core import revocations, signing


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mandate(key, *, delegate="steward-x", scope=None, hours=1):
    now = datetime.now(timezone.utc)
    return signing.build_mandate(
        "principal-a", key, delegate_id=delegate,
        scope=scope or ["demo.echo"],
        valid_from=_iso(now - timedelta(minutes=1)),
        valid_until=_iso(now + timedelta(hours=hours)),
        created_at=_iso(now))


def _now() -> str:
    return _iso(datetime.now(timezone.utc))


class RevocationStatementTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "pub")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_build_verify_round_trip(self) -> None:
        mandate = _mandate(self.key)
        stmt = signing.build_mandate_revocation(
            mandate, self.key, revoked_at=_now(), reason="compromised")
        self.assertEqual(stmt["kind"], "mandate-revocation")
        self.assertEqual(stmt["mandate_id"], mandate["mandate_id"])
        v = signing.verify_mandate_revocation(stmt)
        self.assertTrue(v.valid, v.reason)

    def test_tampered_header_fails(self) -> None:
        stmt = signing.build_mandate_revocation(
            _mandate(self.key), self.key, revoked_at=_now())
        stmt["mandate_id"] = "mnd_other"  # retarget after signing
        v = signing.verify_mandate_revocation(stmt)
        self.assertFalse(v.valid)
        self.assertFalse(v.checks["signature"])

    def test_revocation_revokes_the_mandate(self) -> None:
        mandate = _mandate(self.key)
        stmt = signing.build_mandate_revocation(mandate, self.key, revoked_at=_now())
        mv = signing.verify_mandate(mandate, at_time=_now(), revocations=[stmt])
        self.assertFalse(mv.valid)
        self.assertFalse(mv.checks["not_revoked"])
        # Without the revocation the mandate is fine.
        self.assertTrue(signing.verify_mandate(
            mandate, at_time=_now(), revocations=[]).valid)

    def test_forged_revocation_is_inert(self) -> None:
        # The issuer-only rule: a statement signed by ANY other key — even one
        # that names the target mandate_id and impersonates the principal
        # block — revokes nothing.
        mandate = _mandate(self.key)
        attacker = signing.generate_keypair(Path(self._tmp.name) / "attacker")
        forged_base = signing.build_mandate(
            "principal-a", attacker, delegate_id="steward-x",
            scope=["demo.echo"], valid_from=mandate["valid_from"],
            valid_until=mandate["valid_until"], created_at=mandate["created_at"],
            mandate_id=mandate["mandate_id"])
        forged = signing.build_mandate_revocation(
            forged_base, attacker, revoked_at=_now())
        # Self-consistent (the attacker signed their own statement)...
        self.assertTrue(signing.verify_mandate_revocation(forged).valid)
        # ...but inert against the real mandate: key mismatch.
        mv = signing.verify_mandate(mandate, at_time=_now(), revocations=[forged])
        self.assertTrue(mv.valid, mv.reason)
        self.assertTrue(mv.checks["not_revoked"])

    def test_build_refuses_non_issuer_key(self) -> None:
        mandate = _mandate(self.key)
        attacker = signing.generate_keypair(Path(self._tmp.name) / "attacker2")
        with self.assertRaises(ValueError):
            signing.build_mandate_revocation(mandate, attacker, revoked_at=_now())


class RevocationSidecarTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env = unittest.mock.patch.dict(
            "os.environ", {"CHP_REVOCATION_DIR": self._tmp.name})
        self._env.start()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "pub")

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def test_record_load_and_dedupe(self) -> None:
        stmt = signing.build_mandate_revocation(
            _mandate(self.key), self.key, revoked_at=_now())
        revocations.record_mandate_revocation(stmt)
        revocations.record_mandate_revocation(stmt)  # dupe ignored
        loaded = revocations.load_mandate_revocations()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["mandate_id"], stmt["mandate_id"])


class RevocationGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env = unittest.mock.patch.dict(
            "os.environ", {"CHP_REVOCATION_DIR": self._tmp.name})
        self._env.start()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "pub")
        self.host = LocalCapabilityHost("test-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"echo": payload.get("value")}

        self.host.register(
            CapabilityDescriptor(id="demo.echo", version="1.0.0", description="Echo."),
            handler,
        )

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    async def test_revoked_mandate_is_denied_at_gate_5(self) -> None:
        mandate = _mandate(self.key)
        ok = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "hi"}, mandate=mandate))
        self.assertEqual(ok.outcome, "success")

        revocations.record_mandate_revocation(signing.build_mandate_revocation(
            mandate, self.key, revoked_at=_now(), reason="withdrawn"))

        denied = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "hi"}, mandate=mandate))
        self.assertEqual(denied.outcome, "denied")
        self.assertEqual(denied.denial.code, "mandate_invalid")
        self.assertFalse(denied.denial.details["checks"]["not_revoked"])


class RevocationRouteTests(unittest.TestCase):
    """GET/POST /revocations (spec §10 Revocation): push verifies before
    persisting; pull serves {keys, mandates}."""

    def setUp(self) -> None:
        import threading

        from chp_core.http import create_http_server

        self._tmp = tempfile.TemporaryDirectory()
        self._env = unittest.mock.patch.dict(
            "os.environ", {"CHP_REVOCATION_DIR": self._tmp.name})
        self._env.start()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "pub")
        host = LocalCapabilityHost("route-host", store=SQLiteEvidenceStore(":memory:"))
        self.server = create_http_server(host, bind="127.0.0.1", port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._env.stop()
        self._tmp.cleanup()

    def _post(self, url: str, body: dict) -> dict:
        import json as _json
        import urllib.request

        req = urllib.request.Request(
            url, data=_json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return _json.loads(resp.read())

    def _get(self, url: str) -> dict:
        import json as _json
        import urllib.request

        with urllib.request.urlopen(url, timeout=10) as resp:
            return _json.loads(resp.read())

    def test_post_then_get_round_trip(self) -> None:
        stmt = signing.build_mandate_revocation(
            _mandate(self.key), self.key, revoked_at=_now())
        accepted = self._post(f"{self.base}/revocations", stmt)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["mandate_id"], stmt["mandate_id"])
        served = self._get(f"{self.base}/revocations")
        self.assertEqual([m["mandate_id"] for m in served["mandates"]],
                         [stmt["mandate_id"]])
        self.assertIn("keys", served)

    def test_unverifiable_statement_is_refused_never_stored(self) -> None:
        import urllib.error

        stmt = signing.build_mandate_revocation(
            _mandate(self.key), self.key, revoked_at=_now())
        stmt["mandate_id"] = "mnd_retargeted"  # breaks the signature
        with self.assertRaises(urllib.error.HTTPError) as exc:
            self._post(f"{self.base}/revocations", stmt)
        self.assertEqual(exc.exception.code, 400)
        self.assertEqual(revocations.load_mandate_revocations(), [])


if __name__ == "__main__":
    unittest.main()
