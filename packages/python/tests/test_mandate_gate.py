"""The mandate gate (chp-v0.2.md §10, pipeline gate 5): presented authority
verifies at host time, rebinds the subject, and narrows to its scope."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core import signing


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


class MandateGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("test-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"echo": payload.get("value")}

        self.host.register(
            CapabilityDescriptor(id="demo.echo", version="1.0.0", description="Echo."),
            handler,
        )
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "pub")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    async def test_valid_mandate_rebinds_subject(self) -> None:
        mandate = _mandate(self.key)
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "hi"}, mandate=mandate))
        self.assertEqual(result.outcome, "success")
        events = self.host.replay(result.correlation.correlation_id)
        subj = events[0].get("subject") or {}
        self.assertEqual(subj.get("type"), "mandate")
        self.assertEqual(subj.get("id"), "steward-x")
        self.assertEqual(subj.get("principal"), "principal-a")
        self.assertEqual(subj.get("mandate_id"), mandate["mandate_id"])
        self.assertTrue(subj.get("verified"))

    async def test_expired_mandate_is_mandate_invalid(self) -> None:
        mandate = _mandate(self.key, hours=-1)  # already expired
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", mandate=mandate))
        self.assertEqual(result.outcome, "denied")
        self.assertEqual(result.denial.code, "mandate_invalid")
        self.assertFalse(result.denial.retryable)
        self.assertFalse(result.denial.details["checks"]["temporal"])

    async def test_tampered_mandate_is_mandate_invalid(self) -> None:
        mandate = _mandate(self.key)
        mandate["scope"] = ["*"]  # widened after signing
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", mandate=mandate))
        self.assertEqual(result.denial.code, "mandate_invalid")
        self.assertFalse(result.denial.details["checks"]["signature"])

    async def test_out_of_scope_is_policy_blocked(self) -> None:
        mandate = _mandate(self.key, scope=["other.cap"])
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", mandate=mandate))
        self.assertEqual(result.outcome, "denied")
        self.assertEqual(result.denial.code, "policy_blocked")
        self.assertIn("scope", result.denial.message)

    async def test_wrong_delegate_vs_verified_caller_is_mandate_invalid(self) -> None:
        # Transport auth already verified "alice"; the mandate names steward-x.
        mandate = _mandate(self.key)
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", mandate=mandate,
            subject={"id": "alice", "type": "api_key", "verified": True}))
        self.assertEqual(result.denial.code, "mandate_invalid")
        self.assertFalse(result.denial.details["checks"]["delegate"])

    async def test_matching_delegate_vs_verified_caller_succeeds(self) -> None:
        mandate = _mandate(self.key, delegate="alice")
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "x"}, mandate=mandate,
            subject={"id": "alice", "type": "api_key", "verified": True}))
        self.assertEqual(result.outcome, "success")

    async def test_no_mandate_is_todays_behavior(self) -> None:
        result = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "x"}))
        self.assertEqual(result.outcome, "success")

    async def test_envelope_round_trip_carries_mandate(self) -> None:
        mandate = _mandate(self.key)
        env = InvocationEnvelope(capability_id="demo.echo", mandate=mandate)
        data = env.to_dict()
        self.assertEqual(data["mandate"]["mandate_id"], mandate["mandate_id"])
        self.assertEqual(
            InvocationEnvelope.from_mapping(data).mandate["mandate_id"],
            mandate["mandate_id"])
        # absent stays absent on the wire (additive field)
        self.assertNotIn("mandate", InvocationEnvelope(capability_id="x").to_dict())


if __name__ == "__main__":
    unittest.main()
