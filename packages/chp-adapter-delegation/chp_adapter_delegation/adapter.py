"""DelegationAdapter — governed work handoff as CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* delegation_id, from_session, to_agent, criteria_count — all in evidence.
* work_parcel — included in create evidence (declared delegation intent;
  making handoffs observable is the point of this adapter).
* reason (for reject) — included (governance metadata).
* outcome (for complete) — included if provided (structured result metadata).

Four capabilities:

* ``delegation.create``   — open a delegation envelope; emits delegation_created
* ``delegation.accept``   — accept the delegation; emits delegation_accepted
* ``delegation.complete`` — record a successful completion; emits delegation_completed
* ``delegation.reject``   — reject with a stated reason; emits delegation_rejected
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability
from chp_core.types import DelegationEnvelope, new_id


@dataclass
class DelegationConfig:
    """Configuration for DelegationAdapter (currently stateless; reserved for future use)."""


class DelegationAdapter(BaseAdapter):
    """Governed work handoff — delegation lifecycle with full evidence chain."""

    def __init__(self, config: DelegationConfig | None = None) -> None:
        self._config = config or DelegationConfig()

    @capability(
        id="chp.adapters.delegation.create",
        version="0.1.0",
        category="agent_operations",
        risk="medium",
        description=(
            "Create a governed delegation envelope. "
            "Emits delegation_created. Returns full DelegationEnvelope dict."
        ),
        input_schema={
            "type": "object",
            "required": ["to_agent", "work_parcel"],
            "properties": {
                "delegation_id": {
                    "type": "string",
                    "description": "Stable identifier; auto-generated if omitted.",
                },
                "from_session": {
                    "type": "string",
                    "description": "Session ID of the delegating agent.",
                    "default": "local",
                },
                "to_agent": {
                    "type": "string",
                    "description": "Agent name or capability_id receiving the work.",
                },
                "work_parcel": {
                    "type": "string",
                    "description": "Natural-language description of what is delegated.",
                },
                "acceptance_criteria": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observable conditions for successful completion.",
                    "default": [],
                },
                "context_ref": {
                    "type": "string",
                    "description": "correlation_id of prior context to carry forward.",
                },
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
    )
    async def create(self, ctx: Any, payload: dict) -> dict:
        delegation_id = payload.get("delegation_id") or new_id("del")
        from_session = payload.get("from_session") or "local"
        to_agent = payload["to_agent"]
        work_parcel = payload["work_parcel"]
        criteria = list(payload.get("acceptance_criteria") or [])
        envelope = DelegationEnvelope(
            delegation_id=delegation_id,
            from_session=from_session,
            to_agent=to_agent,
            work_parcel=work_parcel,
            acceptance_criteria=criteria,
            context_ref=payload.get("context_ref"),
            metadata=dict(payload.get("metadata") or {}),
        )
        ctx.emit("delegation_created", {
            "delegation_id": delegation_id,
            "from_session": from_session,
            "to_agent": to_agent,
            "work_parcel": work_parcel,
            "criteria_count": len(criteria),
        })
        return envelope.to_dict()

    @capability(
        id="chp.adapters.delegation.accept",
        version="0.1.0",
        category="agent_operations",
        risk="low",
        description="Accept a pending delegation. Emits delegation_accepted.",
        input_schema={
            "type": "object",
            "required": ["delegation_id"],
            "properties": {
                "delegation_id": {"type": "string"},
                "to_agent": {
                    "type": "string",
                    "description": "Accepting agent name (for evidence; optional).",
                },
            },
            "additionalProperties": False,
        },
    )
    async def accept(self, ctx: Any, payload: dict) -> dict:
        delegation_id = payload["delegation_id"]
        to_agent = payload.get("to_agent", "")
        ctx.emit("delegation_accepted", {
            "delegation_id": delegation_id,
            "to_agent": to_agent,
        })
        return {"delegation_id": delegation_id, "status": "accepted"}

    @capability(
        id="chp.adapters.delegation.complete",
        version="0.1.0",
        category="agent_operations",
        risk="medium",
        description=(
            "Mark a delegation completed with an optional structured outcome. "
            "Emits delegation_completed."
        ),
        input_schema={
            "type": "object",
            "required": ["delegation_id"],
            "properties": {
                "delegation_id": {"type": "string"},
                "outcome": {
                    "type": "object",
                    "description": "Structured result / EvaluationResult dict (optional).",
                },
            },
            "additionalProperties": False,
        },
    )
    async def complete(self, ctx: Any, payload: dict) -> dict:
        delegation_id = payload["delegation_id"]
        outcome = payload.get("outcome")
        ev: dict[str, Any] = {"delegation_id": delegation_id}
        if outcome is not None:
            ev["outcome"] = outcome
        ctx.emit("delegation_completed", ev)
        return {"delegation_id": delegation_id, "status": "completed"}

    @capability(
        id="chp.adapters.delegation.reject",
        version="0.1.0",
        category="agent_operations",
        risk="low",
        description="Reject a delegation with a stated reason. Emits delegation_rejected.",
        input_schema={
            "type": "object",
            "required": ["delegation_id", "reason"],
            "properties": {
                "delegation_id": {"type": "string"},
                "reason": {"type": "string", "minLength": 1},
            },
            "additionalProperties": False,
        },
    )
    async def reject(self, ctx: Any, payload: dict) -> dict:
        delegation_id = payload["delegation_id"]
        reason = payload["reason"]
        ctx.emit("delegation_rejected", {
            "delegation_id": delegation_id,
            "reason": reason,
        })
        return {"delegation_id": delegation_id, "status": "rejected"}
