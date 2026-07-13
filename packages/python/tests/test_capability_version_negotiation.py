"""Cross-host capability-version negotiation (chp-v0.2.md §1.1, proposal 0028): a
caller may require a semver range; a resolved-but-unsatisfied version denies
capability_version_unsupported (distinct from capability_not_found)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, InvocationEnvelope, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.semver import best_satisfying, version_satisfies


class MatcherTests(unittest.TestCase):
    def test_semver_subset(self) -> None:
        self.assertTrue(version_satisfies("1.5.0", "^1.2.0"))
        self.assertFalse(version_satisfies("2.0.0", "^1.2.0"))
        self.assertTrue(version_satisfies("1.2.9", "~1.2.3"))
        self.assertFalse(version_satisfies("1.3.0", "~1.2.3"))
        self.assertTrue(version_satisfies("1.7.0", ">=1.0 <2"))
        self.assertTrue(version_satisfies("1.9.9", "1.x"))
        self.assertFalse(version_satisfies("2.0.0", "1.x"))
        self.assertEqual(best_satisfying(["1.0.0", "1.5.0", "2.0.0"], "^1.0.0"), "1.5.0")


class VersionGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("neg-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"v": "ran"}

        for ver in ("1.0.0", "2.0.0"):
            self.host.register(
                CapabilityDescriptor(id="analyze", version=ver, description="."), handler)

    async def test_compatible_range_resolves(self) -> None:
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="analyze", requested_capability_version="^1.0.0"))
        self.assertEqual(r.outcome, "success")
        self.assertEqual(r.capability_version, "1.0.0")

    async def test_picks_highest_satisfying(self) -> None:
        async def h2(_c, p):
            return {}
        self.host.register(CapabilityDescriptor(id="analyze", version="1.5.0", description="."), h2)
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="analyze", requested_capability_version="^1.0.0"))
        self.assertEqual(r.capability_version, "1.5.0")

    async def test_unsatisfiable_range_is_capability_version_unsupported(self) -> None:
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="analyze", requested_capability_version="^3.0.0"))
        self.assertEqual(r.outcome, "denied")
        self.assertEqual(r.denial.code, "capability_version_unsupported")
        self.assertFalse(r.denial.retryable)
        self.assertEqual(r.denial.details["requested"], "^3.0.0")
        self.assertEqual(sorted(r.denial.details["available"]), ["1.0.0", "2.0.0"])

    async def test_unknown_id_is_still_capability_not_found(self) -> None:
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="nope", requested_capability_version="^1.0.0"))
        self.assertEqual(r.denial.code, "capability_not_found")

    async def test_absent_field_is_unchanged_resolution(self) -> None:
        r = await self.host.ainvoke_envelope(InvocationEnvelope(
            capability_id="analyze", version="2.0.0"))
        self.assertEqual(r.outcome, "success")
        self.assertEqual(r.capability_version, "2.0.0")


if __name__ == "__main__":
    unittest.main()
