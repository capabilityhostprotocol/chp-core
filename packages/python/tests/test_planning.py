"""Tests for PlanningContext, ReflectionContext, and related types (v0.3.2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from chp_core import (
    COGNITION_EVIDENCE_TYPES,
    EvaluationResult,
    PlanDescriptor,
    PlanStep,
    PlanStepStatus,
    PlanningContext,
    ReflectionContext,
    SQLiteEvidenceStore,
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


def _simple_plan(intent: str = "test plan") -> PlanDescriptor:
    return PlanDescriptor(
        plan_id=new_id("plan"),
        intent=intent,
        steps=[
            PlanStep(step_id="s1", description="first step"),
            PlanStep(step_id="s2", description="second step"),
        ],
    )


# ── PlanStep / PlanDescriptor / EvaluationResult types ───────────────────────


def test_plan_step_defaults() -> None:
    s = PlanStep(step_id="s1", description="do something")
    assert s.capability_id is None
    assert s.status == "pending"
    assert s.metadata == {}


def test_plan_step_to_dict() -> None:
    s = PlanStep(step_id="s1", description="test", capability_id="bash", status="running")
    d = s.to_dict()
    assert d["step_id"] == "s1"
    assert d["capability_id"] == "bash"
    assert d["status"] == "running"


def test_plan_descriptor_defaults() -> None:
    p = PlanDescriptor(plan_id="p1", intent="do a thing")
    assert p.steps == []
    assert p.parent_correlation_id is None
    assert p.metadata == {}


def test_plan_descriptor_to_dict_includes_steps() -> None:
    p = _simple_plan()
    d = p.to_dict()
    assert len(d["steps"]) == 2
    assert d["steps"][0]["step_id"] == "s1"


def test_plan_descriptor_from_mapping_minimal() -> None:
    p = PlanDescriptor.from_mapping({"plan_id": "p1", "intent": "minimal"})
    assert p.plan_id == "p1"
    assert p.intent == "minimal"
    assert p.steps == []


def test_plan_descriptor_from_mapping_with_steps() -> None:
    raw = {
        "plan_id": "p2",
        "intent": "with steps",
        "steps": [
            {"step_id": "s1", "description": "first"},
            {"step_id": "s2", "description": "second", "capability_id": "bash"},
        ],
    }
    p = PlanDescriptor.from_mapping(raw)
    assert len(p.steps) == 2
    assert p.steps[1].capability_id == "bash"


def test_evaluation_result_defaults() -> None:
    e = EvaluationResult(score=0.8, rubric="correctness", evaluator="model")
    assert e.evidence_refs == []
    assert e.notes == ""
    assert e.passed is None


def test_evaluation_result_roundtrip() -> None:
    e = EvaluationResult(
        score=0.75,
        rubric="coverage and correctness",
        evaluator="human",
        evidence_refs=["ev_001", "ev_002"],
        notes="Good but missing edge cases",
        passed=True,
    )
    d = e.to_dict()
    assert d["score"] == 0.75
    assert d["rubric"] == "coverage and correctness"
    assert d["evidence_refs"] == ["ev_001", "ev_002"]
    assert d["passed"] is True


# ── PlanningContext — evidence emission ───────────────────────────────────────


def test_planning_context_emits_plan_created_on_enter(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        assert "plan_created" in _types(store, ctx.correlation_id)


def test_planning_context_emits_plan_completed_on_clean_exit(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        corr = ctx.correlation_id
    assert "plan_completed" in _types(store, corr)


def test_planning_context_emits_plan_failed_on_exception(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    corr = None
    with pytest.raises(ValueError):
        with PlanningContext(plan, store_path=store) as ctx:
            corr = ctx.correlation_id
            raise ValueError("something went wrong")
    assert corr is not None
    types = _types(store, corr)
    assert "plan_failed" in types
    assert "plan_completed" not in types


def test_plan_failed_payload_contains_reason(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with pytest.raises(RuntimeError):
        with PlanningContext(plan, store_path=store) as ctx:
            corr = ctx.correlation_id
            raise RuntimeError("oops")
    failed = next(e for e in _events(store, corr) if e["event_type"] == "plan_failed")
    assert failed["payload"]["reason"] == "oops"
    assert failed["payload"]["exception_type"] == "RuntimeError"


def test_step_started_emits_plan_step_started(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_started("s1")
        corr = ctx.correlation_id
    assert "plan_step_started" in _types(store, corr)


def test_step_started_payload_contains_step_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_started("s1")
        corr = ctx.correlation_id
    started = next(e for e in _events(store, corr) if e["event_type"] == "plan_step_started")
    assert started["payload"]["step_id"] == "s1"


def test_step_completed_emits_plan_step_completed(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_completed("s1")
        corr = ctx.correlation_id
    assert "plan_step_completed" in _types(store, corr)


def test_step_completed_payload_has_status_completed(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_completed("s1", result={"output": "done"})
        corr = ctx.correlation_id
    completed = next(e for e in _events(store, corr) if e["event_type"] == "plan_step_completed")
    assert completed["payload"]["status"] == "completed"
    assert completed["payload"]["result"] == {"output": "done"}


def test_step_failed_emits_plan_step_completed_with_failure(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_failed("s1", error="bash returned exit code 1")
        corr = ctx.correlation_id
    ev = next(e for e in _events(store, corr) if e["event_type"] == "plan_step_completed")
    assert ev["payload"]["status"] == "failed"
    assert "bash returned exit code 1" in ev["payload"]["error"]


def test_revise_emits_plan_revised(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.revise("scope changed", added_steps=[PlanStep(step_id="s3", description="extra")])
        corr = ctx.correlation_id
    types = _types(store, corr)
    assert "plan_revised" in types


def test_revise_payload_contains_reason_and_added_steps(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.revise("added auth step", added_steps=[PlanStep(step_id="s3", description="auth")])
        corr = ctx.correlation_id
    revised = next(e for e in _events(store, corr) if e["event_type"] == "plan_revised")
    assert revised["payload"]["reason"] == "added auth step"
    assert len(revised["payload"]["added_steps"]) == 1
    assert revised["payload"]["added_steps"][0]["step_id"] == "s3"


def test_plan_events_share_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        ctx.step_started("s1")
        ctx.step_completed("s1")
        corr = ctx.correlation_id
    events = _events(store, corr)
    assert all(e["correlation"]["correlation_id"] == corr for e in events)


def test_planning_context_custom_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    custom_id = "my-session-id"
    with PlanningContext(plan, store_path=store, correlation_id=custom_id) as ctx:
        assert ctx.correlation_id == custom_id
    assert "plan_created" in _types(store, custom_id)


def test_planning_context_plan_id_property(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = PlanDescriptor(plan_id="specific-plan-id", intent="test")
    with PlanningContext(plan, store_path=store) as ctx:
        assert ctx.plan_id == "specific-plan-id"


def test_plan_created_payload_contains_step_count(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    plan = _simple_plan()
    with PlanningContext(plan, store_path=store) as ctx:
        corr = ctx.correlation_id
    created = next(e for e in _events(store, corr) if e["event_type"] == "plan_created")
    assert created["payload"]["step_count"] == 2


# ── ReflectionContext — evidence emission ─────────────────────────────────────


def test_reflection_context_emits_reflection_started_on_enter(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("test quality", store_path=store) as r:
        assert "reflection_started" in _types(store, r.correlation_id)


def test_reflection_context_emits_reflection_completed_on_exit(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("test quality", store_path=store) as r:
        corr = r.correlation_id
    assert "reflection_completed" in _types(store, corr)


def test_reflection_add_content_appears_in_completed_payload(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("quality", store_path=store) as r:
        r.add("First observation.")
        r.add("Second observation.")
        corr = r.correlation_id
    completed = next(e for e in _events(store, corr) if e["event_type"] == "reflection_completed")
    assert "First observation." in completed["payload"]["content"]
    assert "Second observation." in completed["payload"]["content"]
    assert completed["payload"]["content_parts"] == 2


def test_reflection_no_content_gives_empty_string(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("empty", store_path=store) as r:
        corr = r.correlation_id
    completed = next(e for e in _events(store, corr) if e["event_type"] == "reflection_completed")
    assert completed["payload"]["content"] == ""


def test_reflection_score_emits_outcome_scored(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("eval", store_path=store) as r:
        r.score(EvaluationResult(score=0.85, rubric="completeness", evaluator="model"))
        corr = r.correlation_id
    assert "outcome_scored" in _types(store, corr)


def test_reflection_score_payload_contains_evaluation_fields(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("eval", store_path=store) as r:
        r.score(EvaluationResult(
            score=0.7,
            rubric="edge case coverage",
            evaluator="human",
            notes="Missing timeout tests",
            passed=False,
        ))
        corr = r.correlation_id
    scored = next(e for e in _events(store, corr) if e["event_type"] == "outcome_scored")
    assert scored["payload"]["score"] == 0.7
    assert scored["payload"]["rubric"] == "edge case coverage"
    assert scored["payload"]["evaluator"] == "human"
    assert scored["payload"]["notes"] == "Missing timeout tests"
    assert scored["payload"]["passed"] is False


def test_reflection_events_share_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("subject", store_path=store) as r:
        r.add("content")
        r.score(EvaluationResult(score=1.0, rubric="r", evaluator="model"))
        corr = r.correlation_id
    events = _events(store, corr)
    assert all(e["correlation"]["correlation_id"] == corr for e in events)


def test_reflection_custom_correlation_id(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    custom_id = "custom-reflection-id"
    with ReflectionContext("test", store_path=store, correlation_id=custom_id) as r:
        assert r.correlation_id == custom_id


def test_reflection_started_payload_contains_subject(tmp_path: Path) -> None:
    store = str(tmp_path / "ev.sqlite")
    with ReflectionContext("my subject", store_path=store) as r:
        corr = r.correlation_id
    started = next(e for e in _events(store, corr) if e["event_type"] == "reflection_started")
    assert started["payload"]["subject"] == "my subject"


# ── COGNITION_EVIDENCE_TYPES completeness ─────────────────────────────────────


def test_planning_events_in_cognition_types() -> None:
    planning_events = {
        "plan_created", "plan_step_started", "plan_step_completed",
        "plan_revised", "plan_completed", "plan_failed",
    }
    assert planning_events.issubset(COGNITION_EVIDENCE_TYPES)


def test_reflection_events_in_cognition_types() -> None:
    reflection_events = {"reflection_started", "reflection_completed", "outcome_scored"}
    assert reflection_events.issubset(COGNITION_EVIDENCE_TYPES)


def test_memory_events_still_in_cognition_types() -> None:
    memory_events = {"memory_read", "memory_written", "memory_deleted"}
    assert memory_events.issubset(COGNITION_EVIDENCE_TYPES)
