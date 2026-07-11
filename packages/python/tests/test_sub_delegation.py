"""Sub-delegation (chp-v0.2.md §10, proposal 0009): attenuation-only mandate
chains — build/verify, the attenuation invariant, the delegate join, depth
cap, revocation suffix-kill, and byte-compatibility with single-hop mandates."""

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
from chp_core.types import CorrelationContext


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _iso(datetime.now(timezone.utc))


class SubDelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        # root principal, the worker (root's delegate), the tool-runner (leaf).
        self.root_key = signing.generate_keypair(d / "root")
        self.worker_key = signing.generate_keypair(d / "worker")
        now = datetime.now(timezone.utc)
        self.vf = _iso(now - timedelta(minutes=1))
        self.root_vu = _iso(now + timedelta(hours=4))
        self.created = _iso(now)
        # root grants the worker a broad scope + a 4h window.
        self.root = signing.build_mandate(
            "root-principal", self.root_key, delegate_id="worker",
            scope=["chp.adapters.audit.*", "demo.echo"],
            valid_from=self.vf, valid_until=self.root_vu, created_at=self.created)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _sub(self, *, scope, valid_until, delegate="tool-runner"):
        return signing.build_sub_mandate(
            self.root, self.worker_key, delegate_id=delegate,
            scope=scope, valid_from=self.vf, valid_until=valid_until,
            created_at=self.created)

    def test_valid_chain_verifies(self) -> None:
        sub = self._sub(scope=["demo.echo"], valid_until=_iso(
            datetime.now(timezone.utc) + timedelta(hours=1)))
        self.assertEqual(sub["depth"], 1)
        self.assertEqual(sub["parent_id"], self.root["mandate_id"])
        v = signing.verify_mandate(sub, at_time=_now(),
                                   capability_id="demo.echo", delegate_id="tool-runner")
        self.assertTrue(v.valid, v.reason)
        self.assertTrue(v.checks["parent_valid"])
        self.assertEqual(signing.mandate_root_principal(sub), "root-principal")

    def test_scope_widening_rejected_at_build(self) -> None:
        # demo.other is NOT in the parent scope → build refuses.
        with self.assertRaises(ValueError) as ctx:
            self._sub(scope=["demo.other"], valid_until=self.root_vu)
        self.assertIn("attenuation_scope", str(ctx.exception))

    def test_scope_widening_rejected_at_verify(self) -> None:
        # Forge: build a valid sub, then widen its scope post-signing.
        sub = self._sub(scope=["demo.echo"], valid_until=self.root_vu)
        sub["scope"] = ["chp.*", "demo.echo"]  # broader than parent, tampered
        v = signing.verify_mandate(sub, at_time=_now())
        self.assertFalse(v.valid)
        # signature breaks (scope is header-signed) AND attenuation fails
        self.assertFalse(v.checks["signature"])

    def test_window_lengthening_rejected(self) -> None:
        longer = _iso(datetime.now(timezone.utc) + timedelta(hours=8))  # > root's 4h
        with self.assertRaises(ValueError) as ctx:
            self._sub(scope=["demo.echo"], valid_until=longer)
        self.assertIn("attenuation_window", str(ctx.exception))

    def test_broken_delegate_join_rejected(self) -> None:
        # A sub whose principal is NOT the parent's delegate is inert. Sign a
        # sub with a key attesting a different host_id, then splice it under root.
        stranger = signing.generate_keypair(Path(self._tmp.name) / "stranger")
        # build_sub_mandate sets principal from parent.delegate_id, so forge by
        # hand: a mandate claiming parent=root but principal.host_id != "worker".
        forged = signing.build_mandate(
            "stranger", stranger, delegate_id="tool-runner", scope=["demo.echo"],
            valid_from=self.vf, valid_until=self.root_vu, created_at=self.created)
        forged["depth"] = 1
        forged["parent_id"] = self.root["mandate_id"]
        forged["parent"] = self.root
        # re-sign the tampered header so signature passes; join must still fail
        forged["signature"]["signature"] = signing._sign(
            stranger._private, signing._canon(signing.mandate_header(forged)))
        v = signing.verify_mandate(forged, at_time=_now())
        self.assertFalse(v.valid)
        self.assertFalse(v.checks["delegate_join"])

    def test_revoke_root_kills_the_sub(self) -> None:
        sub = self._sub(scope=["demo.echo"], valid_until=self.root_vu)
        # sub is valid before revocation
        self.assertTrue(signing.verify_mandate(sub, at_time=_now(), revocations=[]).valid)
        # revoke the ROOT (signed by the root principal — issuer-only)
        rev = signing.build_mandate_revocation(self.root, self.root_key, revoked_at=_now())
        v = signing.verify_mandate(sub, at_time=_now(), revocations=[rev])
        self.assertFalse(v.valid, "revoking the root must kill the sub")
        self.assertFalse(v.checks["parent_valid"])

    def test_depth_cap_blocks_over_deep_chain(self) -> None:
        # Hand-nest depth beyond the cap and confirm it fails without recursing
        # to the interpreter limit.
        node = self.root
        signer = self.worker_key
        delegate = "worker"
        for i in range(signing._MAX_MANDATE_DEPTH + 2):
            # each level's principal must be the parent's delegate; keep it simple
            # by making a self-consistent-but-over-deep chain via raw depth stamps
            child = dict(node)
            child["depth"] = i + 1
            node = child
        node["parent"] = self.root
        v = signing.verify_mandate(node, at_time=_now())
        self.assertFalse(v.valid)

    def test_single_hop_mandate_unchanged(self) -> None:
        # A mandate with no parent has the classic 8-field header and no new keys.
        self.assertNotIn("depth", self.root)
        self.assertNotIn("parent_id", self.root)
        self.assertNotIn("parent", self.root)
        header = signing.mandate_header(self.root)
        self.assertEqual(set(header), set(signing._MANDATE_HEADER_FIELDS))
        self.assertTrue(signing.verify_mandate(
            self.root, at_time=_now(), delegate_id="worker").valid)


class SubDelegationGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_chain_invoke_records_root_principal(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        root_key = signing.generate_keypair(d / "root")
        worker_key = signing.generate_keypair(d / "worker")
        now = datetime.now(timezone.utc)
        vf, vu, created = _iso(now - timedelta(minutes=1)), _iso(now + timedelta(hours=2)), _iso(now)
        root = signing.build_mandate(
            "root-principal", root_key, delegate_id="worker",
            scope=["demo.echo"], valid_from=vf, valid_until=vu, created_at=created)
        sub = signing.build_sub_mandate(
            root, worker_key, delegate_id="tool-runner", scope=["demo.echo"],
            valid_from=vf, valid_until=_iso(now + timedelta(hours=1)), created_at=created)

        host = LocalCapabilityHost("gate-host", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="demo.echo", version="1.0.0",
                                           description="."), handler)
        result = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={}, mandate=sub,
            correlation=CorrelationContext(correlation_id="chain-invoke"),
            subject={"id": "tool-runner", "type": "api_key", "verified": True}))
        self.assertEqual(result.outcome, "success")
        subj = host.replay("chain-invoke")[0].get("subject") or {}
        self.assertEqual(subj.get("type"), "mandate")
        self.assertEqual(subj.get("id"), "tool-runner")
        self.assertEqual(subj.get("principal"), "worker")           # immediate
        self.assertEqual(subj.get("root_principal"), "root-principal")  # ultimate

    async def test_widened_sub_denied_at_gate(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        root_key = signing.generate_keypair(d / "root")
        worker_key = signing.generate_keypair(d / "worker")
        now = datetime.now(timezone.utc)
        vf, vu, created = _iso(now - timedelta(minutes=1)), _iso(now + timedelta(hours=2)), _iso(now)
        root = signing.build_mandate(
            "root-principal", root_key, delegate_id="worker",
            scope=["demo.echo"], valid_from=vf, valid_until=vu, created_at=created)
        sub = signing.build_sub_mandate(
            root, worker_key, delegate_id="tool-runner", scope=["demo.echo"],
            valid_from=vf, valid_until=_iso(now + timedelta(hours=1)), created_at=created)
        sub["scope"] = ["demo.echo", "demo.secret"]  # widened post-signing

        host = LocalCapabilityHost("gate-host2", store=SQLiteEvidenceStore(":memory:"))

        async def handler(_ctx, payload):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="demo.echo", version="1.0.0",
                                           description="."), handler)
        result = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="demo.echo", payload={}, mandate=sub,
            subject={"id": "tool-runner", "type": "api_key", "verified": True}))
        self.assertEqual(result.outcome, "denied")
        self.assertEqual(result.denial.code, "mandate_invalid")


if __name__ == "__main__":
    unittest.main()
