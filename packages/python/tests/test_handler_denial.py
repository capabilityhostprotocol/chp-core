"""A capability handler may raise CapabilityDenied to report a DISPATCH-time authority
failure (e.g. a provider 401) as outcome=denied, not failure — distinguishing
"not authorized" from "authorized but broke" for a post-admission failure the
governance gates cannot see. (rad:d96efd3)"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDenied,
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)


def _host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("denial-host", store=SQLiteEvidenceStore(":memory:"))

    async def denies(_ctx, _payload):
        raise CapabilityDenied("provider rejected the credential (401)",
                               code="com.example.credential_rejected", retryable=False)

    async def breaks(_ctx, _payload):
        raise RuntimeError("boom")

    host.register(CapabilityDescriptor(id="prov.denies", version="1.0.0", description="."), denies)
    host.register(CapabilityDescriptor(id="prov.breaks", version="1.0.0", description="."), breaks)
    return host


class HandlerDenialTests(unittest.IsolatedAsyncioTestCase):
    async def test_capability_denied_maps_to_denied_outcome(self) -> None:
        host = _host()
        result = await host.ainvoke_envelope(
            InvocationEnvelope(capability_id="prov.denies", payload={}))
        self.assertEqual(result.outcome, "denied")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.denial)
        self.assertEqual(result.denial.code, "com.example.credential_rejected")
        self.assertFalse(result.denial.retryable)
        # it is recorded as execution_denied (not execution_failed)
        kinds = {e["event_type"] for e in host.store.query()}
        self.assertIn("execution_denied", kinds)
        self.assertNotIn("execution_failed", kinds)

    async def test_plain_exception_is_still_failure(self) -> None:
        host = _host()
        result = await host.ainvoke_envelope(
            InvocationEnvelope(capability_id="prov.breaks", payload={}))
        self.assertEqual(result.outcome, "failure")
        self.assertFalse(result.success)
        self.assertIsNone(getattr(result, "denial", None))


if __name__ == "__main__":
    unittest.main()
