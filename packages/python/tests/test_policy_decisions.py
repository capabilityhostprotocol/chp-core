"""Richer policy decision vocabulary + versioned decision records (proposal 0036).
The policy engine renders one of 6 decisions; each blocking decision maps to a reserved
denial code at the governance gate and carries a decision record (decision, matched_rule,
policy_version, explanation, required_next_action). sandbox_only fails closed to
policy_blocked (no sandbox execution mode). Backward-compatible: a rule with no decision
means deny, exactly as before."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.policy import BlockPattern, PolicyConfig, evaluate_policy
from chp_core.types import DenialReason

_CODE = {"deny": "policy_blocked", "requires_approval": "approval_required",
         "requires_escalation": "escalation_required",
         "requires_more_evidence": "evidence_required", "sandbox_only": "policy_blocked"}


def _pol(decision: str) -> PolicyConfig:
    return PolicyConfig(version="7", block_patterns=[
        BlockPattern("w.cap", "cmd", "trip", "matched", decision=decision)])


def test_new_codes_are_reserved() -> None:
    assert "escalation_required" in DenialReason.RESERVED_CODES
    assert "evidence_required" in DenialReason.RESERVED_CODES


def test_each_decision_maps_to_its_code_and_records() -> None:
    for decision in ("deny", "requires_approval", "requires_escalation",
                     "requires_more_evidence", "sandbox_only"):
        host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"), policy=_pol(decision))

        async def w(_c, _p):
            return {"ok": 1}

        host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), w)
        r = asyncio.run(host.ainvoke("w.cap", {"cmd": "trip"}))
        assert r.outcome == "denied", decision
        d = r.denial
        assert d.code == _CODE[decision], (decision, d.code)
        # decision record
        assert d.details["decision"] == decision
        assert d.details["matched_rule"] == "block_pattern:w.cap.cmd"
        assert d.details["policy_version"] == "7"
        assert d.details["explanation"] == "matched"
        # retryable only for the action-required decisions
        assert d.retryable is (decision in ("requires_approval", "requires_escalation",
                                            "requires_more_evidence"))


def test_default_decision_is_deny_backward_compat() -> None:
    # A block-pattern with no explicit decision denies, exactly as pre-0036.
    r = evaluate_policy("w.cap", {"cmd": "trip"}, PolicyConfig(
        block_patterns=[BlockPattern("w.cap", "cmd", "trip", "x")]))
    assert r.decision == "deny" and r.should_block is True


def test_no_match_allows() -> None:
    r = evaluate_policy("w.cap", {"cmd": "safe"}, _pol("deny"))
    assert r.decision == "allow" and r.should_block is False


def test_audit_only_records_but_does_not_block() -> None:
    pol = _pol("deny")
    pol.audit_only = True
    r = evaluate_policy("w.cap", {"cmd": "trip"}, pol)
    assert r.decision == "deny" and r.should_block is False  # advisory


def test_unknown_decision_in_policy_file_is_rejected() -> None:
    from chp_core.policy import PolicyError, _parse_policy
    try:
        _parse_policy({"block_patterns": [
            {"capability_id": "w.cap", "field": "cmd", "pattern": "x", "decision": "bogus"}]})
        assert False, "expected PolicyError"
    except PolicyError:
        pass


def test_policy_decision_vector_matches() -> None:
    vec = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "policy-decision.json"
    doc = json.loads(vec.read_text())
    for c in doc["cases"]:
        pol = PolicyConfig(block_patterns=[
            BlockPattern(p["capability_id"], p["field"], p["pattern"], p.get("reason", "."),
                         p.get("decision", "deny")) for p in c.get("block_patterns", [])])
        r = evaluate_policy(c["capability_id"], c.get("input", {}), pol)
        assert r.decision == c["decision"], c["note"]
        assert r.should_block is c["blocks"], c["note"]
        if c["blocks"]:
            assert _CODE[r.decision] == c["code"], c["note"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
