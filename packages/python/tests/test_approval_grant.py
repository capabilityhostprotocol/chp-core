"""Resumable invocation + provable approval grants (proposal 0037). A capability
requiring approval denies approval_required; an approver-signed grant bound to the exact
invocation_id + payload commitment lets it resume and execute EXACTLY ONCE — duplicate-
execution protection preserved across the approve→execute boundary. The grant is verified
offline like a mandate; a payload swap after approval is rejected."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncio

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.host import _stringify_floats
from chp_core.signing import build_approval_grant, generate_keypair, verify_approval_grant
from chp_core.store import _payload_commitment
from chp_core.types import AutonomyProfile, InvocationEnvelope


def _commit(payload: dict) -> str:
    return _payload_commitment(_stringify_floats(payload))


def _run(coro):
    return asyncio.run(coro)


def test_grant_build_and_verify() -> None:
    k = generate_keypair(tempfile.mkdtemp())
    g = build_approval_grant(k, invocation_id="inv-1", payload_commitment="pc",
                             approval_id="ap-1", valid_until="2099-01-01T00:00:00Z")
    assert verify_approval_grant(g, at_time="2026-07-15T00:00:00Z").valid
    assert not verify_approval_grant(g, at_time="2099-06-01T00:00:00Z").valid   # expired
    tampered = dict(g); tampered["invocation_id"] = "inv-EVIL"
    assert not verify_approval_grant(tampered, at_time="2026-07-15T00:00:00Z").valid  # sig breaks
    assert not verify_approval_grant(g, at_time="2026-07-15T00:00:00Z",
                                     expected_approver_key="other").valid       # wrong pin
    assert verify_approval_grant("not-a-dict", at_time="x").valid is False       # fail-closed


def _approval_host():
    calls = {"n": 0}
    host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def work(_c, p):
        calls["n"] += 1
        return {"echo": p.get("x")}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description=".",
                                       autonomy=AutonomyProfile(tier="approval_required")), work)
    return host, calls, generate_keypair(tempfile.mkdtemp())


def test_resume_executes_exactly_once() -> None:
    host, calls, approver = _approval_host()
    payload = {"x": 42}
    inv = "inv-fixed"

    async def go():
        r1 = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="w.cap", invocation_id=inv, payload=payload))
        assert r1.outcome == "denied" and r1.denial.code == "approval_required"
        grant = build_approval_grant(approver, invocation_id=inv,
                                     payload_commitment=_commit(payload),
                                     approval_id="ap-1", valid_until="2099-01-01T00:00:00Z")
        r2 = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="w.cap", invocation_id=inv, payload=payload, approval_ref=grant))
        assert r2.outcome == "success" and r2.data == {"echo": 42}
        # replay the same id again → terminal result, handler NOT re-run
        r3 = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="w.cap", invocation_id=inv, payload=payload, approval_ref=grant))
        assert r3.outcome == "success" and r3.replayed

    _run(go())
    assert calls["n"] == 1, f"exactly-once violated: handler ran {calls['n']}x"


def test_payload_swap_after_approval_is_rejected() -> None:
    host, calls, approver = _approval_host()
    # grant commits payload {"x": 1}; resume presents {"x": 999} → grant check fails.
    grant = build_approval_grant(approver, invocation_id="inv-2",
                                 payload_commitment=_commit({"x": 1}),
                                 approval_id="ap-2", valid_until="2099-01-01T00:00:00Z")
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id="inv-2", payload={"x": 999}, approval_ref=grant)))
    assert r.outcome == "denied" and r.denial.code == "approval_required"
    assert calls["n"] == 0


def test_expired_grant_does_not_resume() -> None:
    host, calls, approver = _approval_host()
    payload = {"x": 7}
    grant = build_approval_grant(approver, invocation_id="inv-3",
                                 payload_commitment=_commit(payload),
                                 approval_id="ap-3", valid_until="2000-01-01T00:00:00Z")  # past
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id="inv-3", payload=payload, approval_ref=grant)))
    assert r.outcome == "denied" and r.denial.code == "approval_required"
    assert calls["n"] == 0


def test_wrong_invocation_grant_does_not_resume() -> None:
    host, calls, approver = _approval_host()
    payload = {"x": 5}
    # grant is for a DIFFERENT invocation_id
    grant = build_approval_grant(approver, invocation_id="some-other-inv",
                                 payload_commitment=_commit(payload),
                                 approval_id="ap-4", valid_until="2099-01-01T00:00:00Z")
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id="inv-4", payload=payload, approval_ref=grant)))
    assert r.outcome == "denied" and r.denial.code == "approval_required"


def test_no_grant_still_denies() -> None:
    host, calls, _ = _approval_host()
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id="inv-5", payload={"x": 1})))
    assert r.outcome == "denied" and r.denial.code == "approval_required"


def test_approval_ref_omit_when_absent_byte_identical() -> None:
    import hashlib
    e = InvocationEnvelope(capability_id="c.cap", invocation_id="i1",
                           requested_at="2026-01-01T00:00:00Z")
    assert "approval_ref" not in e.to_dict()
    canon = lambda o: hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()
    d0 = e.to_dict()
    e.approval_ref = {"kind": "approval-grant"}
    assert "approval_ref" in e.to_dict()
    e.approval_ref = None
    assert canon(e.to_dict()) == canon(d0)


def test_approval_grant_vector_matches() -> None:
    vec = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "approval-grant.json"
    doc = json.loads(vec.read_text())
    for c in doc["cases"]:
        assert verify_approval_grant(c["grant"], at_time=c["at_time"]).valid is c["valid"], c["note"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
