"""Tests for AutonomyProfile, budget gates, and autonomy evidence events (v0.3.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from chp_core import (
    AUTONOMY_EVIDENCE_TYPES,
    AutonomyProfile,
    CapabilityDescriptor,
    CorrelationContext,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core.types import RollbackPolicy, new_id


# ── Helpers ───────────────────────────────────────────────────────────────────


def _host(tmp_path: Path) -> tuple[LocalCapabilityHost, SQLiteEvidenceStore, str]:
    store_path = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store_path)
    host = LocalCapabilityHost("test-host", store=store_obj)
    return host, store_obj, store_path


def _events(store_path: str, correlation_id: str) -> list[dict]:
    s = SQLiteEvidenceStore(store_path)
    evs = s.by_correlation(correlation_id)
    s.close()
    return evs


def _types(store_path: str, correlation_id: str) -> list[str]:
    return [e["event_type"] for e in _events(store_path, correlation_id)]


def _register_noop(host: LocalCapabilityHost, capability_id: str = "test.noop",
                   autonomy: AutonomyProfile | None = None) -> None:
    from chp_core.types import CapabilityCategory

    async def _handler(ctx, payload):
        return {"ok": True}

    host.register(
        CapabilityDescriptor(
            id=capability_id,
            version="0.1.0",
            description="No-op test capability.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            autonomy=autonomy,
        ),
        _handler,
    )


def _corr(session_id: str) -> CorrelationContext:
    return CorrelationContext(correlation_id=session_id)


# ── A. AutonomyProfile type ───────────────────────────────────────────────────


def test_autonomy_profile_defaults() -> None:
    a = AutonomyProfile()
    assert a.tier == "supervised"
    assert a.spend_limit is None
    assert a.spend_units == 1.0
    assert a.action_limit is None
    assert a.rollback_policy == "none"


def test_autonomy_profile_to_dict_contains_all_fields() -> None:
    d = AutonomyProfile().to_dict()
    assert set(d.keys()) == {"tier", "spend_limit", "spend_units", "action_limit", "rollback_policy"}


def test_autonomy_profile_spend_limit_none_serialises_as_null() -> None:
    d = AutonomyProfile(spend_limit=None).to_dict()
    assert d["spend_limit"] is None


def test_autonomy_profile_action_limit_roundtrip() -> None:
    a = AutonomyProfile(action_limit=5)
    assert a.to_dict()["action_limit"] == 5


def test_autonomy_profile_rollback_policy_variants() -> None:
    for val in ("none", "checkpoint", "full"):
        a = AutonomyProfile(rollback_policy=val)  # type: ignore[arg-type]
        assert a.rollback_policy == val


def test_autonomy_profile_spend_units_custom() -> None:
    a = AutonomyProfile(spend_units=2.5)
    assert a.to_dict()["spend_units"] == 2.5


def test_capability_descriptor_omits_autonomy_key_when_none() -> None:
    d = CapabilityDescriptor(id="x", version="0.1.0", description="test").to_dict()
    assert "autonomy" not in d


# ── B. AUTONOMY_EVIDENCE_TYPES constant ──────────────────────────────────────


def test_autonomy_evidence_types_contains_budget_exceeded() -> None:
    assert "budget_exceeded" in AUTONOMY_EVIDENCE_TYPES


def test_autonomy_evidence_types_contains_approval_requested() -> None:
    assert "approval_requested" in AUTONOMY_EVIDENCE_TYPES


def test_autonomy_evidence_types_contains_approval_granted() -> None:
    assert "approval_granted" in AUTONOMY_EVIDENCE_TYPES


def test_autonomy_evidence_types_contains_approval_denied() -> None:
    assert "approval_denied" in AUTONOMY_EVIDENCE_TYPES


# ── C. No-op when autonomy=None ───────────────────────────────────────────────


def test_no_autonomy_profile_succeeds_normally(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=None)
    result = host.invoke("test.noop")
    assert result.success


def test_no_autonomy_profile_evidence_trail_unchanged(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=None)
    corr = new_id("corr")
    result = host.invoke("test.noop", correlation=_corr(corr))
    types = _types(store_path, corr)
    assert types == ["execution_started", "execution_completed"]
    assert not any(t in AUTONOMY_EVIDENCE_TYPES for t in types)


# ── D. action_limit enforcement ───────────────────────────────────────────────


def test_action_limit_allows_up_to_limit(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=3))
    corr = new_id("corr")
    for _ in range(3):
        r = host.invoke("test.noop", correlation=_corr(corr))
        assert r.success


def test_action_limit_denies_at_limit_plus_one(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=2))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert not r.success
    assert r.outcome == "denied"


def test_action_limit_denied_result_has_correct_code(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert r.denial is not None
    assert r.denial.code == "budget_exceeded"


def test_action_limit_denied_not_retryable(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert r.denial is not None
    assert r.denial.retryable is False


def test_action_limit_emits_budget_exceeded_event(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    assert "budget_exceeded" in _types(store_path, corr)


def test_action_limit_budget_exceeded_payload_has_limit_type(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    assert ev["payload"]["limit_type"] == "action_limit"


def test_action_limit_budget_exceeded_payload_has_actions_taken(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=2))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    assert ev["payload"]["actions_taken"] == 2


def test_action_limit_budget_exceeded_carries_rollback_policy(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1, rollback_policy="checkpoint"))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    assert ev["payload"]["rollback_policy"] == "checkpoint"


# ── E. spend_limit enforcement ────────────────────────────────────────────────


def test_spend_limit_allows_up_to_limit(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=3.0, spend_units=1.0))
    corr = new_id("corr")
    for _ in range(3):
        r = host.invoke("test.noop", correlation=_corr(corr))
        assert r.success


def test_spend_limit_denies_when_exceeded(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=3.0, spend_units=1.0))
    corr = new_id("corr")
    for _ in range(3):
        host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert not r.success
    assert r.denial.code == "budget_exceeded"


def test_spend_limit_denied_code_is_budget_exceeded(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=1.0))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert r.denial.code == "budget_exceeded"


def test_spend_limit_with_custom_spend_units(tmp_path: Path) -> None:
    # spend_limit=4.0, units=2.0 → 2 invocations = 4.0 spend → 3rd denied
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=4.0, spend_units=2.0))
    corr = new_id("corr")
    r1 = host.invoke("test.noop", correlation=_corr(corr))
    r2 = host.invoke("test.noop", correlation=_corr(corr))
    r3 = host.invoke("test.noop", correlation=_corr(corr))
    assert r1.success
    assert r2.success
    assert not r3.success


def test_spend_limit_payload_has_spend_so_far(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=2.0, spend_units=1.0))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    # Floats are string-encoded in hashed evidence (chp-stable-v1 §2 forbids
    # floats in canonicalized content — cross-language hash portability).
    assert ev["payload"]["spend_so_far"] == "2.0"
    assert float(ev["payload"]["spend_so_far"]) == 2.0


def test_spend_limit_payload_has_spend_limit_and_spend_units(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=5.0, spend_units=2.5))
    corr = new_id("corr")
    for _ in range(3):
        host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    # String-encoded in hashed evidence (chp-stable-v1 §2), numeric on parse.
    assert ev["payload"]["spend_limit"] == "5.0"
    assert ev["payload"]["spend_units"] == "2.5"
    assert (float(ev["payload"]["spend_limit"]), float(ev["payload"]["spend_units"])) == (5.0, 2.5)


def test_spend_limit_not_retryable(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(spend_limit=1.0))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    r = host.invoke("test.noop", correlation=_corr(corr))
    assert r.denial.retryable is False


# ── F. tier == "approval_required" ───────────────────────────────────────────


def test_approval_required_tier_always_denies(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    r = host.invoke("test.noop")
    assert not r.success
    assert r.outcome == "denied"


def test_approval_required_denied_code(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    r = host.invoke("test.noop")
    assert r.denial.code == "approval_required"


def test_approval_required_is_retryable(tmp_path: Path) -> None:
    host, _, _ = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    r = host.invoke("test.noop")
    assert r.denial.retryable is True


def test_approval_required_emits_approval_requested_event(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    assert "approval_requested" in _types(store_path, corr)


def test_approval_required_payload_has_tier_field(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "approval_requested")
    assert ev["payload"]["tier"] == "approval_required"


# ── G. Evidence trail integrity ───────────────────────────────────────────────


def test_budget_exceeded_event_precedes_execution_denied(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    types = _types(store_path, corr)
    budget_idx = types.index("budget_exceeded")
    denied_idx = types.index("execution_denied")
    assert budget_idx < denied_idx


def test_budget_exceeded_outcome_is_denied(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(action_limit=1))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "budget_exceeded")
    assert ev.get("outcome") == "denied"


def test_approval_requested_outcome_is_denied(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=AutonomyProfile(tier="approval_required"))
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    ev = next(e for e in _events(store_path, corr) if e["event_type"] == "approval_requested")
    assert ev.get("outcome") == "denied"


def test_autonomy_events_not_emitted_for_plain_capabilities(tmp_path: Path) -> None:
    host, _, store_path = _host(tmp_path)
    _register_noop(host, autonomy=None)
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    types = set(_types(store_path, corr))
    assert types.isdisjoint(AUTONOMY_EVIDENCE_TYPES)


# ── H. store.count_by_correlation_event_type ─────────────────────────────────


def test_count_by_correlation_event_type_counts_only_matching_type(tmp_path: Path) -> None:
    store_path = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store_path)
    host = LocalCapabilityHost("test-host", store=store_obj)
    _register_noop(host)
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    host.invoke("test.noop", correlation=_corr(corr))

    count = store_obj.count_by_correlation_event_type(corr, "execution_started")
    total = store_obj.count_by_correlation(corr)
    assert count == 2
    assert total > count  # total includes execution_completed etc.
    store_obj.close()


def test_count_by_correlation_event_type_zero_for_unknown_type(tmp_path: Path) -> None:
    store_path = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store_path)
    host = LocalCapabilityHost("test-host", store=store_obj)
    _register_noop(host)
    corr = new_id("corr")
    host.invoke("test.noop", correlation=_corr(corr))
    count = store_obj.count_by_correlation_event_type(corr, "nonexistent_type")
    assert count == 0
    store_obj.close()


def test_count_by_correlation_event_type_returns_int(tmp_path: Path) -> None:
    store_path = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store_path)
    count = store_obj.count_by_correlation_event_type("no-such-corr", "execution_started")
    assert isinstance(count, int)
    assert count == 0
    store_obj.close()
