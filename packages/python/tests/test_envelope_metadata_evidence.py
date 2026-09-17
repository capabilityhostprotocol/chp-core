"""A caller's InvocationEnvelope.metadata (e.g. run_id/effect_id/tenant_id) is carried
into the execution_started evidence payload, so downstream can query causal linkage
natively. Events with no caller metadata omit the key (byte-identical). (rad:e0f0826)"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, InvocationEnvelope, LocalCapabilityHost, SQLiteEvidenceStore


def _host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("meta-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_ctx, payload):
        return {"echo": payload.get("v")}

    host.register(CapabilityDescriptor(id="m.echo", version="1.0.0", description="."), echo)
    return host


def _started_payload(host) -> dict:
    ev = [e for e in host.store.query() if e["event_type"] == "execution_started"]
    assert len(ev) == 1
    payload = ev[0]["payload"]
    return payload if isinstance(payload, dict) else {}


class EnvelopeMetadataEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_metadata_carried_into_execution_started(self) -> None:
        host = _host()
        await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="m.echo", payload={"v": 1},
            metadata={"run_id": "run_abc", "effect_id": "eff_xyz", "tenant_id": "acme"}))
        meta = _started_payload(host).get("metadata")
        self.assertIsNotNone(meta)
        self.assertEqual(meta["run_id"], "run_abc")
        self.assertEqual(meta["effect_id"], "eff_xyz")
        self.assertEqual(meta["tenant_id"], "acme")

    async def test_no_metadata_key_when_absent(self) -> None:
        host = _host()
        await host.ainvoke_envelope(InvocationEnvelope(capability_id="m.echo", payload={"v": 2}))
        # byte-identity for pre-metadata events: the key is simply not present
        self.assertNotIn("metadata", _started_payload(host))


if __name__ == "__main__":
    unittest.main()
