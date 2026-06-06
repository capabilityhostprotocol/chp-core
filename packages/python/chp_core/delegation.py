"""DelegationContext and register_planning_capability — governed handoff for CHP (v0.3.3).

DelegationContext records a work handoff as replayable CHP evidence without requiring a
LocalCapabilityHost.  register_planning_capability wires PlanningContext into a host so
plan declaration becomes a policy-gated, evidence-wrapped capability invocation.

Usage::

    envelope = DelegationEnvelope(
        delegation_id=new_id("del"),
        from_session="session-abc",
        to_agent="chp_agent.research",
        work_parcel="Summarise the v0.3 changelog",
        acceptance_criteria=["Summary is under 500 words", "Covers all 3 patches"],
    )

    with DelegationContext(envelope, store_path=".chp/evidence.sqlite") as ctx:
        ctx.accept()
        # ... sub-agent does work ...
        ctx.complete(outcome={"word_count": 312})

    # On a host: register planning as a governed capability
    register_planning_capability(host)
    result = host.invoke("planning.create_plan", {"plan_id": "p1", "intent": "..."})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .hooks import default_store_path
from .planning import _emit_cognition_event
from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    DelegationEnvelope,
    JSON,
    PlanDescriptor,
    new_id,
)

if TYPE_CHECKING:
    from .host import LocalCapabilityHost


# ── DelegationContext ─────────────────────────────────────────────────────────


class DelegationContext:
    """Context manager that records a delegation handoff as CHP evidence.

    On enter  → emits ``delegation_created``
    On clean exit (if not already resolved) → emits ``delegation_completed``
    On exception exit (if not already resolved) → emits ``delegation_rejected``

    Between enter and exit, call:
        ``accept()``                        → ``delegation_accepted``
        ``reject(reason)``                  → ``delegation_rejected`` (resolves; suppresses __exit__)
        ``complete(outcome=None)``          → ``delegation_completed`` (resolves; suppresses __exit__)
        ``reassign(to_agent, reason="")``   → ``delegation_reassigned`` (non-terminal)
    """

    def __init__(
        self,
        envelope: DelegationEnvelope,
        *,
        store_path: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self._envelope = envelope
        self._store_path = store_path or default_store_path()
        self._correlation_id = correlation_id or new_id("del_corr")
        self._resolved = False

    @property
    def delegation_id(self) -> str:
        return self._envelope.delegation_id

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def __enter__(self) -> "DelegationContext":
        env = self._envelope
        _emit_cognition_event(
            "delegation_created",
            self._store_path,
            self._correlation_id,
            {
                **env.to_dict(),
                "criteria_count": len(env.acceptance_criteria),
            },
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._resolved:
            return
        if exc_type is not None:
            _emit_cognition_event(
                "delegation_rejected",
                self._store_path,
                self._correlation_id,
                {
                    "delegation_id": self._envelope.delegation_id,
                    "reason": str(exc_val),
                    "exception_type": exc_type.__name__ if exc_type else None,
                },
            )
        else:
            _emit_cognition_event(
                "delegation_completed",
                self._store_path,
                self._correlation_id,
                {
                    "delegation_id": self._envelope.delegation_id,
                    "outcome": None,
                },
            )

    def accept(self) -> None:
        """Emit ``delegation_accepted`` — sub-agent has taken ownership of the work."""
        _emit_cognition_event(
            "delegation_accepted",
            self._store_path,
            self._correlation_id,
            {
                "delegation_id": self._envelope.delegation_id,
                "to_agent": self._envelope.to_agent,
            },
        )

    def reject(self, reason: str) -> None:
        """Emit ``delegation_rejected`` explicitly and mark the context resolved."""
        _emit_cognition_event(
            "delegation_rejected",
            self._store_path,
            self._correlation_id,
            {
                "delegation_id": self._envelope.delegation_id,
                "reason": reason,
                "exception_type": None,
            },
        )
        self._resolved = True

    def complete(self, outcome: Any = None) -> None:
        """Emit ``delegation_completed`` explicitly and mark the context resolved."""
        payload: JSON = {
            "delegation_id": self._envelope.delegation_id,
            "outcome": outcome if isinstance(outcome, (dict, list, str, int, float, bool, type(None))) else str(outcome),
        }
        _emit_cognition_event(
            "delegation_completed",
            self._store_path,
            self._correlation_id,
            payload,
        )
        self._resolved = True

    def reassign(self, to_agent: str, reason: str = "") -> None:
        """Emit ``delegation_reassigned`` — non-terminal, work handed to a different agent."""
        _emit_cognition_event(
            "delegation_reassigned",
            self._store_path,
            self._correlation_id,
            {
                "delegation_id": self._envelope.delegation_id,
                "from_agent": self._envelope.to_agent,
                "to_agent": to_agent,
                "reason": reason,
            },
        )
        self._envelope = DelegationEnvelope(
            delegation_id=self._envelope.delegation_id,
            from_session=self._envelope.from_session,
            to_agent=to_agent,
            work_parcel=self._envelope.work_parcel,
            acceptance_criteria=self._envelope.acceptance_criteria,
            context_ref=self._envelope.context_ref,
            metadata=self._envelope.metadata,
        )


# ── register_planning_capability ─────────────────────────────────────────────


def register_planning_capability(host: "LocalCapabilityHost") -> None:
    """Register ``planning.create_plan`` as a governed CHP capability on *host*.

    Unlike bare PlanningContext, invocations through the host pass through policy
    gates and are wrapped in execution_started / execution_completed evidence.

    Payload: PlanDescriptor-compatible dict (``plan_id``, ``intent``, ``steps``).
    Returns: ``{"plan_id": "<id>"}``
    """
    from .host import CapabilityExecutionContext

    async def _create_plan(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
        plan = PlanDescriptor.from_mapping(payload or {})
        ctx.emit(
            "plan_created",
            {
                "plan_id": plan.plan_id,
                "intent": plan.intent,
                "step_count": len(plan.steps),
                "steps": [s.to_dict() for s in plan.steps],
                "parent_correlation_id": plan.parent_correlation_id,
            },
        )
        return {"plan_id": plan.plan_id}

    host.register(
        CapabilityDescriptor(
            id="planning.create_plan",
            version="0.1.0",
            description="Formally declare a plan as governed CHP evidence.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            tags=["planning", "cognition", "delegation"],
            emits=["execution_started", "execution_completed", "execution_failed", "plan_created"],
        ),
        _create_plan,
    )
