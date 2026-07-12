"""max_invocations enforcement (chp-v0.2.md §10, proposal 0026): a mandate's signed
use-count cap; the gate counts distinct invocations per mandate_id and denies
mandate_exhausted past the cap."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (CapabilityDescriptor, InvocationEnvelope, LocalCapabilityHost,
                      SQLiteEvidenceStore, signing)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mandate(key, *, max_invocations=None):
    now = datetime.now(timezone.utc)
    return signing.build_mandate(
        "principal-a", key, delegate_id="steward-x", scope=["demo.echo"],
        valid_from=_iso(now - timedelta(minutes=1)),
        valid_until=_iso(now + timedelta(hours=1)), created_at=_iso(now),
        max_invocations=max_invocations)


class MaxInvocationsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("cap-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"echo": payload.get("value")}

        self.host.register(
            CapabilityDescriptor(id="demo.echo", version="1.0.0", description="Echo."), handler)
        self._tmp = tempfile.TemporaryDirectory()
        self.key = signing.generate_keypair(Path(self._tmp.name) / "k")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    async def test_cap_of_two_denies_the_third(self) -> None:
        mandate = _mandate(self.key, max_invocations=2)
        outcomes = []
        for _ in range(3):
            r = await self.host.ainvoke_envelope(InvocationEnvelope(
                capability_id="demo.echo", payload={"value": "x"}, mandate=mandate))
            outcomes.append(r)
        self.assertEqual([o.outcome for o in outcomes], ["success", "success", "denied"])
        third = outcomes[2]
        self.assertEqual(third.denial.code, "mandate_exhausted")
        self.assertFalse(third.denial.retryable)
        self.assertEqual(third.denial.details["used"], 2)
        self.assertEqual(third.denial.details["max_invocations"], 2)

    async def test_replay_same_invocation_does_not_double_count(self) -> None:
        mandate = _mandate(self.key, max_invocations=2)
        # The SAME invocation_id twice consumes ONE use (idempotent replay + the
        # composite-key record), so a second distinct invocation still succeeds.
        env = InvocationEnvelope(capability_id="demo.echo", payload={"value": "a"},
                                 mandate=mandate, invocation_id="inv-fixed-1")
        r1 = await self.host.ainvoke_envelope(env)
        r1b = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "a"}, mandate=mandate,
            invocation_id="inv-fixed-1"))
        r2 = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "b"}, mandate=mandate))
        self.assertEqual(r1.outcome, "success")
        self.assertEqual(r1b.outcome, "success")  # replay, not a new use
        self.assertEqual(r2.outcome, "success")   # still within cap of 2
        self.assertEqual(self.host.store.count_mandate_uses(mandate["mandate_id"]), 2)

    async def test_uncapped_mandate_is_unlimited(self) -> None:
        mandate = _mandate(self.key)  # no max_invocations
        self.assertNotIn("max_invocations", mandate)
        for _ in range(5):
            r = await self.host.ainvoke_envelope(InvocationEnvelope(
                capability_id="demo.echo", payload={"value": "x"}, mandate=mandate))
            self.assertEqual(r.outcome, "success")

    async def test_tampered_cap_fails_signature(self) -> None:
        mandate = _mandate(self.key, max_invocations=1)
        mandate["max_invocations"] = 999  # raise the cap without re-signing
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={"value": "x"}, mandate=mandate))
        self.assertEqual(r.outcome, "denied")
        self.assertEqual(r.denial.code, "mandate_invalid")  # header signature broke


if __name__ == "__main__":
    unittest.main()
