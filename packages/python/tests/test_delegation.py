"""Tests for DelegationContext, DelegationEnvelope, and register_planning_capability (v0.3.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from chp_core import (
    COGNITION_EVIDENCE_TYPES,
    DelegationContext,
    DelegationEnvelope,
    DelegationStatus,
    EvaluationResult,
    LocalCapabilityHost,
    PlanDescriptor,
    PlanStep,
    SQLiteEvidenceStore,
    register_planning_capability,
)
from chp_core.types import new_id


# ── Helpers ───────────────────────────────────────────────────────────────────


def _events(store_path: str, correlation_id: str) -> list[dict]:
    s = SQLiteEvidenceStore(store_path)
    evs = s.by_correlation(correlation_id)
    s.close()
    return evs


def _types(store_path: str, correlation_id: str) -> list[str]:
    return [e["event_type"] for e in _events(store_path, correlation_id)]


def _simple_envelope() -> DelegationEnvelope:
    return DelegationEnvelope(
        delegation_id=new_id("del"),
        from_session="session-abc",
        to_agent="chp_agent.research",
        work_parcel="Summarise the v0.3 changelog",
        acceptance_criteria=["Under 500 words", "Covers all patches"],
    )


# ── DelegationEnvelope types ──────────────────────────────────────────────────


def test_delegation_envelope_defaults() -> None:
    e = DelegationEnvelope(
        delegation_id="d1",
        from_session="s1",
        to_agent="agent-b",
        work_parcel="do work",
    )
    assert e.acceptance_criteria == []
    assert e.context_ref is None
    assert e.metadata == {}


def test_delegation_envelope_to_dict() -> None:
    e = DelegationEnvelope(
        delegation_id="d1",
        from_session="s1",
        to_agent="agent-b",
        work_parcel="do work",
        acceptance_criteria=["criterion 1"],
    )
    d = e.to_dict()
    assert d["delegation_id"] == "d1"
    assert d["from_session"] == "s1"
    assert d["acceptance_criteria"] == ["criterion 1"]


def test_delegation_envelope_from_mapping_minimal() -> None:
    e = DelegationEnvelope.from_mapping({
        "delegation_id": "d1",
        "from_session": "s1",
        "to_agent": "agent-b",
        "work_parcel": "do work",
    })
    assert e.delegation_id == "d1"
    assert e.acceptance_criteria == []
    assert e.context_ref is None


def test_delegation_envelope_from_mapping_full() -> None:
    e = DelegationEnvelope.from_mapping({
        "delegation_id": "d2",
        "from_session": "s2",
        "to_agent": "agent-c",
        "work_parcel": "full work",
        "acceptance_criteria": ["a", "b"],
        "context_ref": "corr-123",
        "metadata": {"priority": "high"},
    })
    assert e.acceptance_criteria == ["a", "b"]
    assert e.context_ref == "corr-123"
    assert e.metadata == {"priority": "high"}


def test_delegation_envelope_acceptance_criteria_defaults_to_empty() -> None:
    e = DelegationEnvelope.from_mapping({
        "delegation_id": "d3",
        "from_session": "s3",
        "to_agent": "a",
        "work_parcel": "x",
    })
    assert isinstance(e.acceptance_criteria, list)
    assert len(e.acceptance_criteria) == 0


# ── DelegationContext — core lifecycle ────────────────────────────────────────


def test_delegation_emits_created_on_enter(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        assert "delegation_created" in _types(store, ctx.correlation_id)


def test_delegation_created_payload_contains_work_parcel(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    env = _simple_envelope()
    with DelegationContext(env, store_path=store) as ctx:
        corr = ctx.correlation_id
    created = next(e for e in _events(store, corr) if e["event_type"] == "delegation_created")
    assert created["payload"]["work_parcel"] == env.work_parcel


def test_delegation_created_payload_contains_from_and_to_agent(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    env = _simple_envelope()
    with DelegationContext(env, store_path=store) as ctx:
        corr = ctx.correlation_id
    created = next(e for e in _events(store, corr) if e["event_type"] == "delegation_created")
    assert created["payload"]["from_session"] == env.from_session
    assert created["payload"]["to_agent"] == env.to_agent


def test_delegation_created_payload_contains_acceptance_criteria(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    env = _simple_envelope()
    with DelegationContext(env, store_path=store) as ctx:
        corr = ctx.correlation_id
    created = next(e for e in _events(store, corr) if e["event_type"] == "delegation_created")
    assert created["payload"]["acceptance_criteria"] == env.acceptance_criteria
    assert created["payload"]["criteria_count"] == 2


def test_delegation_emits_completed_on_clean_exit(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        corr = ctx.correlation_id
    assert "delegation_completed" in _types(store, corr)


def test_delegation_emits_rejected_on_exception(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    corr = None
    with pytest.raises(RuntimeError):
        with DelegationContext(_simple_envelope(), store_path=store) as ctx:
            corr = ctx.correlation_id
            raise RuntimeError("downstream failed")
    assert corr is not None
    types = _types(store, corr)
    assert "delegation_rejected" in types
    assert "delegation_completed" not in types


def test_delegation_rejected_payload_contains_reason_and_exception_type(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with pytest.raises(ValueError):
        with DelegationContext(_simple_envelope(), store_path=store) as ctx:
            corr = ctx.correlation_id
            raise ValueError("bad input")
    rejected = next(e for e in _events(store, corr) if e["event_type"] == "delegation_rejected")
    assert rejected["payload"]["reason"] == "bad input"
    assert rejected["payload"]["exception_type"] == "ValueError"


# ── DelegationContext — explicit state methods ────────────────────────────────


def test_accept_emits_delegation_accepted(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.accept()
        corr = ctx.correlation_id
    assert "delegation_accepted" in _types(store, corr)


def test_accept_payload_contains_delegation_id_and_to_agent(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    env = _simple_envelope()
    with DelegationContext(env, store_path=store) as ctx:
        ctx.accept()
        corr = ctx.correlation_id
    accepted = next(e for e in _events(store, corr) if e["event_type"] == "delegation_accepted")
    assert accepted["payload"]["delegation_id"] == env.delegation_id
    assert accepted["payload"]["to_agent"] == env.to_agent


def test_reject_explicit_emits_delegation_rejected(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.reject("out of scope")
        corr = ctx.correlation_id
    assert "delegation_rejected" in _types(store, corr)


def test_reject_explicit_sets_resolved_suppresses_exit_emission(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.reject("out of scope")
        corr = ctx.correlation_id
    types = _types(store, corr)
    rejected = [t for t in types if t == "delegation_rejected"]
    assert len(rejected) == 1  # exactly one, __exit__ did not re-emit
    assert "delegation_completed" not in types


def test_complete_explicit_emits_delegation_completed(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.complete(outcome={"word_count": 312})
        corr = ctx.correlation_id
    assert "delegation_completed" in _types(store, corr)


def test_complete_explicit_sets_resolved_suppresses_exit_emission(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.complete()
        corr = ctx.correlation_id
    completed = [t for t in _types(store, corr) if t == "delegation_completed"]
    assert len(completed) == 1


def test_complete_with_outcome_carries_outcome_in_payload(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.complete(outcome={"word_count": 312})
        corr = ctx.correlation_id
    completed = next(e for e in _events(store, corr) if e["event_type"] == "delegation_completed")
    assert completed["payload"]["outcome"] == {"word_count": 312}


def test_reassign_emits_delegation_reassigned(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.reassign("chp_agent.summariser", reason="original agent unavailable")
        corr = ctx.correlation_id
    assert "delegation_reassigned" in _types(store, corr)


def test_reassign_payload_contains_to_agent_and_reason(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.reassign("chp_agent.summariser", reason="unavailable")
        corr = ctx.correlation_id
    reassigned = next(e for e in _events(store, corr) if e["event_type"] == "delegation_reassigned")
    assert reassigned["payload"]["to_agent"] == "chp_agent.summariser"
    assert reassigned["payload"]["reason"] == "unavailable"
    assert reassigned["payload"]["from_agent"] == "chp_agent.research"


def test_reassign_is_non_terminal_exit_still_emits(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.reassign("chp_agent.summariser")
        corr = ctx.correlation_id
    types = _types(store, corr)
    assert "delegation_reassigned" in types
    assert "delegation_completed" in types  # __exit__ still fires


# ── DelegationContext — correlation & properties ──────────────────────────────


def test_delegation_events_share_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with DelegationContext(_simple_envelope(), store_path=store) as ctx:
        ctx.accept()
        ctx.complete(outcome="done")
        corr = ctx.correlation_id
    events = _events(store, corr)
    assert all(e["correlation"]["correlation_id"] == corr for e in events)


def test_delegation_custom_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    custom = "my-delegation-corr"
    with DelegationContext(_simple_envelope(), store_path=store, correlation_id=custom) as ctx:
        assert ctx.correlation_id == custom
    assert "delegation_created" in _types(store, custom)


def test_delegation_id_property(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    env = _simple_envelope()
    with DelegationContext(env, store_path=store) as ctx:
        assert ctx.delegation_id == env.delegation_id


# ── register_planning_capability ─────────────────────────────────────────────


def test_register_planning_capability_registers_on_host(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store)
    host = LocalCapabilityHost("test-host", store=store_obj)
    register_planning_capability(host)
    # A successful invocation confirms the capability was registered
    result = host.invoke("planning.create_plan", {"plan_id": "p-reg", "intent": "check registration"})
    assert result.success


def test_planning_create_plan_invocation_succeeds(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store)
    host = LocalCapabilityHost("test-host", store=store_obj)
    register_planning_capability(host)
    result = host.invoke("planning.create_plan", {
        "plan_id": "p-test",
        "intent": "do a thing",
        "steps": [],
    })
    assert result.success


def test_planning_create_plan_returns_plan_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store)
    host = LocalCapabilityHost("test-host", store=store_obj)
    register_planning_capability(host)
    result = host.invoke("planning.create_plan", {"plan_id": "p-xyz", "intent": "test"})
    assert result.data["plan_id"] == "p-xyz"


def test_planning_create_plan_emits_plan_created_event(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store)
    host = LocalCapabilityHost("test-host", store=store_obj)
    register_planning_capability(host)
    result = host.invoke("planning.create_plan", {
        "plan_id": "p-abc",
        "intent": "test plan",
        "steps": [{"step_id": "s1", "description": "first"}],
    })
    evs = _events(store, result.correlation.correlation_id)
    types = [e["event_type"] for e in evs]
    assert "plan_created" in types


def test_planning_create_plan_emits_execution_lifecycle(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    store_obj = SQLiteEvidenceStore(store)
    host = LocalCapabilityHost("test-host", store=store_obj)
    register_planning_capability(host)
    result = host.invoke("planning.create_plan", {"plan_id": "p-lc", "intent": "lifecycle test"})
    evs = _events(store, result.correlation.correlation_id)
    types = [e["event_type"] for e in evs]
    assert "execution_started" in types
    assert "execution_completed" in types


# ── COGNITION_EVIDENCE_TYPES completeness ─────────────────────────────────────


def test_delegation_events_in_cognition_types() -> None:
    delegation_events = {
        "delegation_created",
        "delegation_accepted",
        "delegation_completed",
        "delegation_rejected",
        "delegation_reassigned",
    }
    assert delegation_events.issubset(COGNITION_EVIDENCE_TYPES)


def test_prior_cognition_events_still_present() -> None:
    prior = {
        "memory_read", "memory_written", "memory_deleted",
        "plan_created", "plan_step_started", "plan_step_completed",
        "plan_revised", "plan_completed", "plan_failed",
        "reflection_started", "reflection_completed", "outcome_scored",
    }
    assert prior.issubset(COGNITION_EVIDENCE_TYPES)
