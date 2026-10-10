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


def test_grant_refused_when_it_outlives_a_depended_on_bound() -> None:
    # CHP-TEMP-003: a grant MUST NOT outlive any mandatory evidence/authority validity bound its
    # admission depends on. Minting one that would is refused; within-bounds still mints.
    import pytest
    k = generate_keypair(tempfile.mkdtemp())
    with pytest.raises(ValueError):
        build_approval_grant(k, invocation_id="inv-1", payload_commitment="pc", approval_id="ap-1",
                             valid_until="2027-01-01T00:00:00Z",
                             bound_by=["2026-09-01T00:00:00Z"])  # grant outlives the evidence bound
    g = build_approval_grant(k, invocation_id="inv-1", payload_commitment="pc", approval_id="ap-1",
                             valid_until="2026-08-01T00:00:00Z", bound_by=["2026-09-01T00:00:00Z"])
    assert verify_approval_grant(g, at_time="2026-07-15T00:00:00Z").valid
    tampered = dict(g)
    tampered["invocation_id"] = "inv-EVIL"
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
    def canon(o):
        return hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()
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


def test_execution_grant_generalization() -> None:
    """proposal 0043 (CHP-CORE-030): an approval grant generalized with execution-truth
    bindings + audience + single-use budget verifies; the new fields are SIGNED (tampering
    breaks the signature); an audience mismatch is rejected (CHP-CORE-009); and a grant
    minted without them carries none of the new keys (backward compat)."""
    import jsonschema

    k = generate_keypair(tempfile.mkdtemp())
    digest = "sha256:" + "a" * 64
    g = build_approval_grant(
        k, invocation_id="inv-1", payload_commitment="pc", approval_id="ap-1",
        valid_until="2099-01-01T00:00:00Z", invocation_digest=digest,
        action_digest=digest, binding_id="binding_1", audience="executor-A", max_attempts=1,
    )
    schema = json.loads(
        (Path(__file__).resolve().parents[3] / "schemas/chp-approval-grant.schema.json").read_text()
    )
    jsonschema.validate(g, schema)
    assert g["invocation_digest"] == digest and g["audience"] == "executor-A"

    assert verify_approval_grant(g, at_time="2026-07-15T00:00:00Z",
                                 expected_audience="executor-A").valid
    assert not verify_approval_grant(g, at_time="2026-07-15T00:00:00Z",
                                     expected_audience="executor-B").valid  # wrong executor

    tampered = dict(g)
    tampered["invocation_digest"] = "sha256:" + "b" * 64
    assert not verify_approval_grant(tampered, at_time="2026-07-15T00:00:00Z").valid  # signed

    plain = build_approval_grant(k, invocation_id="inv-1", payload_commitment="pc",
                                 approval_id="ap-1", valid_until="2099-01-01T00:00:00Z")
    assert not (set(plain) & {"invocation_digest", "action_digest", "binding_id",
                              "audience", "max_attempts"})
    assert verify_approval_grant(plain, at_time="2026-07-15T00:00:00Z").valid


# ── A4: approver-identity anchoring (reject unanchored self-signed grants under strict mode) ──

def test_strict_mode_rejects_unanchored_self_signed_grant(monkeypatch) -> None:
    """With CHP_HOST_REQUIRE_PINNED_APPROVER on and NO approver pinned, a grant self-signed by an
    arbitrary key is refused — a caller who reaches the endpoint cannot forge its own approval."""
    monkeypatch.delenv("CHP_HOST_APPROVER_KEYS", raising=False)
    monkeypatch.setenv("CHP_HOST_REQUIRE_PINNED_APPROVER", "1")
    host, calls, approver = _approval_host()
    payload, inv = {"x": 1}, "inv-a4-strict"
    grant = build_approval_grant(approver, invocation_id=inv, payload_commitment=_commit(payload),
                                 approval_id="ap", valid_until="2099-01-01T00:00:00Z")
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id=inv, payload=payload, approval_ref=grant)))
    assert r.outcome == "denied" and r.denial.code == "approval_required"
    assert calls["n"] == 0


def test_strict_mode_accepts_pinned_approver(monkeypatch) -> None:
    """Strict mode + the grant's approver IS the pinned key → resumes exactly as before."""
    host, calls, approver = _approval_host()
    payload, inv = {"x": 2}, "inv-a4-pinned"
    grant = build_approval_grant(approver, invocation_id=inv, payload_commitment=_commit(payload),
                                 approval_id="ap", valid_until="2099-01-01T00:00:00Z")
    monkeypatch.setenv("CHP_HOST_APPROVER_KEYS", grant["approver"])   # pin the operator key
    monkeypatch.setenv("CHP_HOST_REQUIRE_PINNED_APPROVER", "1")
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id=inv, payload=payload, approval_ref=grant)))
    assert r.outcome == "success" and r.data == {"echo": 2}


def test_unanchored_grant_accepted_but_evidenced_by_default(monkeypatch) -> None:
    """Migration default (flag off): an unanchored grant still resumes — the fleet is not broken — but
    the approval_grant_verified event records approver_anchored=False so the unanchored path is auditable."""
    monkeypatch.delenv("CHP_HOST_APPROVER_KEYS", raising=False)
    monkeypatch.delenv("CHP_HOST_REQUIRE_PINNED_APPROVER", raising=False)
    host, calls, approver = _approval_host()
    payload, inv = {"x": 3}, "inv-a4-migrate"
    grant = build_approval_grant(approver, invocation_id=inv, payload_commitment=_commit(payload),
                                 approval_id="ap", valid_until="2099-01-01T00:00:00Z")
    r = _run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="w.cap", invocation_id=inv, payload=payload, approval_ref=grant)))
    assert r.outcome == "success"
    evs = [e for e in host.store.all() if e["event_type"] == "approval_grant_verified"]
    assert evs and evs[0]["payload"].get("approver_anchored") is False


def test_forged_grant_rejected__identity_must_bind_to_key_material() -> None:
    """SECURITY (rad 0ae5fec): the approver identity MUST be cryptographically bound to the signing
    key material. An attacker who signs with their OWN key but overwrites `approver` + `signature.key_id`
    to a trusted approver's (public) key_id — leaving their own pubkey embedded — must be REJECTED, even
    when that approver is pinned. Before the fix verify_approval_grant verified the signature against the
    grant's own embedded pubkey while only string-comparing the self-asserted approver fields, so the
    forgery passed (a total authority bypass)."""
    import base64

    from chp_core.signing import _canon, _sign, approval_grant_header, key_id_for

    legit = generate_keypair(tempfile.mkdtemp())
    attacker = generate_keypair(tempfile.mkdtemp())
    assert legit.key_id != attacker.key_id

    g = build_approval_grant(attacker, invocation_id="inv-1", payload_commitment="pc",
                             approval_id="ap-1", valid_until="2099-01-01T00:00:00Z")
    # Forge the identity: claim to be `legit`, keep the attacker's embedded pubkey, re-sign with the
    # attacker's private key over the (now legit-claiming) header.
    g["approver"] = legit.key_id
    g["signature"]["key_id"] = legit.key_id
    g["signature"]["signature"] = _sign(attacker._private, _canon(approval_grant_header(g)))

    # The embedded pubkey's REAL key_id is the attacker's — proof the legit approver never signed.
    assert key_id_for(base64.b64decode(g["approver_identity"]["public_key"])) == attacker.key_id
    v = verify_approval_grant(g, at_time="2026-07-15T00:00:00Z", expected_approver_key=legit.key_id)
    assert not v.valid, "forged grant (approver identity not bound to key material) must be rejected"


def test_honest_grant_still_verifies_after_key_binding() -> None:
    """The key-material binding MUST NOT break honest grants: for a real grant,
    key_id_for(embedded pubkey) == approver == signature.key_id already holds."""
    k = generate_keypair(tempfile.mkdtemp())
    g = build_approval_grant(k, invocation_id="inv-1", payload_commitment="pc",
                             approval_id="ap-1", valid_until="2099-01-01T00:00:00Z")
    assert verify_approval_grant(g, at_time="2026-07-15T00:00:00Z",
                                 expected_approver_key=k.key_id).valid
