"""PlanningContext and ReflectionContext — observable agent cognition for CHP.

Both context managers write directly to a SQLiteEvidenceStore so agent
planning and reflection become replayable CHP evidence without requiring a
full LocalCapabilityHost.

Usage::

    plan = PlanDescriptor(
        plan_id=new_id("plan"),
        intent="Add tests for the memory module",
        steps=[
            PlanStep(step_id="s1", description="Read existing test patterns"),
            PlanStep(step_id="s2", description="Write test_memory.py"),
        ],
    )

    with PlanningContext(plan, store_path=".chp/evidence.sqlite") as ctx:
        ctx.step_started("s1")
        # ... do work ...
        ctx.step_completed("s1")
        ctx.step_started("s2")
        ctx.step_completed("s2", result={"tests_written": 41})

    with ReflectionContext("test quality", store_path=".chp/evidence.sqlite") as r:
        r.add("Tests cover CRUD, scope isolation, and evidence emission.")
        r.score(EvaluationResult(score=0.9, rubric="coverage and correctness", evaluator="model"))
"""

from __future__ import annotations

from typing import Any

from .hooks import default_store_path
from .store import SQLiteEvidenceStore
from .types import (
    CorrelationContext,
    EvaluationResult,
    ExecutionEvidence,
    JSON,
    PlanDescriptor,
    PlanStep,
    new_id,
    utc_now,
)


# ── Internal helper ───────────────────────────────────────────────────────────


def _emit_cognition_event(
    event_type: str,
    store_path: str,
    correlation_id: str,
    payload: JSON,
) -> str:
    """Append one cognition evidence event; return its event_id."""
    store = SQLiteEvidenceStore(store_path)
    ev = store.append(
        ExecutionEvidence(
            event_id=new_id("ev"),
            event_type=event_type,
            invocation_id=new_id("inv"),
            capability_id="chp.cognition",
            capability_version=None,
            host_id="local",
            correlation=CorrelationContext(correlation_id=correlation_id),
            timestamp=utc_now(),
            outcome=None,
            payload=payload,
            redacted=False,
        )
    )
    store.close()
    return ev.event_id


# ── PlanningContext ───────────────────────────────────────────────────────────


class PlanningContext:
    """Context manager that records plan execution as CHP evidence.

    On enter → emits ``plan_created``
    On clean exit → emits ``plan_completed``
    On exception exit → emits ``plan_failed``

    Between enter and exit call:
        ``step_started(step_id)``          → ``plan_step_started``
        ``step_completed(step_id, result)`` → ``plan_step_completed``
        ``step_failed(step_id, error)``    → ``plan_step_completed`` (status=failed)
        ``revise(reason, added_steps)``    → ``plan_revised``
    """

    def __init__(
        self,
        plan: PlanDescriptor,
        *,
        store_path: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self._plan = plan
        self._store_path = store_path or default_store_path()
        self._correlation_id = correlation_id or new_id("plan_corr")

    @property
    def plan_id(self) -> str:
        return self._plan.plan_id

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def __enter__(self) -> "PlanningContext":
        _emit_cognition_event(
            "plan_created",
            self._store_path,
            self._correlation_id,
            {
                "plan_id": self._plan.plan_id,
                "intent": self._plan.intent,
                "step_count": len(self._plan.steps),
                "steps": [s.to_dict() for s in self._plan.steps],
                "parent_correlation_id": self._plan.parent_correlation_id,
                "metadata": self._plan.metadata,
            },
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            _emit_cognition_event(
                "plan_failed",
                self._store_path,
                self._correlation_id,
                {
                    "plan_id": self._plan.plan_id,
                    "reason": str(exc_val),
                    "exception_type": exc_type.__name__ if exc_type else None,
                },
            )
        else:
            _emit_cognition_event(
                "plan_completed",
                self._store_path,
                self._correlation_id,
                {"plan_id": self._plan.plan_id},
            )

    def step_started(self, step_id: str) -> None:
        _emit_cognition_event(
            "plan_step_started",
            self._store_path,
            self._correlation_id,
            {"plan_id": self._plan.plan_id, "step_id": step_id},
        )

    def step_completed(self, step_id: str, result: Any = None) -> None:
        payload: JSON = {
            "plan_id": self._plan.plan_id,
            "step_id": step_id,
            "status": "completed",
        }
        if result is not None:
            payload["result"] = result if isinstance(result, dict) else {"value": result}
        _emit_cognition_event("plan_step_completed", self._store_path, self._correlation_id, payload)

    def step_failed(self, step_id: str, error: str) -> None:
        _emit_cognition_event(
            "plan_step_completed",
            self._store_path,
            self._correlation_id,
            {"plan_id": self._plan.plan_id, "step_id": step_id, "status": "failed", "error": error},
        )

    def revise(self, reason: str, added_steps: list[PlanStep] | None = None) -> None:
        _emit_cognition_event(
            "plan_revised",
            self._store_path,
            self._correlation_id,
            {
                "plan_id": self._plan.plan_id,
                "reason": reason,
                "added_steps": [s.to_dict() for s in (added_steps or [])],
            },
        )


# ── ReflectionContext ─────────────────────────────────────────────────────────


class ReflectionContext:
    """Context manager that records an agent reflection as CHP evidence.

    On enter → emits ``reflection_started``
    On exit  → emits ``reflection_completed`` (includes accumulated content)

    Between enter and exit call:
        ``add(content)``     → accumulate reflection text (merged on __exit__)
        ``score(result)``    → emits ``outcome_scored`` immediately
    """

    def __init__(
        self,
        subject: str,
        *,
        store_path: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self._subject = subject
        self._store_path = store_path or default_store_path()
        self._correlation_id = correlation_id or new_id("refl_corr")
        self._content: list[str] = []

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def __enter__(self) -> "ReflectionContext":
        _emit_cognition_event(
            "reflection_started",
            self._store_path,
            self._correlation_id,
            {"subject": self._subject},
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        _emit_cognition_event(
            "reflection_completed",
            self._store_path,
            self._correlation_id,
            {
                "subject": self._subject,
                "content": "\n".join(self._content),
                "content_parts": len(self._content),
            },
        )

    def add(self, content: str) -> None:
        """Accumulate reflection content; merged into ``reflection_completed`` on exit."""
        self._content.append(content)

    def score(self, result: EvaluationResult) -> None:
        """Emit ``outcome_scored`` immediately with the evaluation result."""
        _emit_cognition_event(
            "outcome_scored",
            self._store_path,
            self._correlation_id,
            {
                "subject": self._subject,
                **result.to_dict(),
            },
        )
