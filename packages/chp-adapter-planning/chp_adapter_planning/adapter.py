"""PlanningAdapter — observable agent cognition as CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Plan intent and step descriptions — included (they are declared agent cognition,
  not secrets or diff content).
* Revision reasons — included (declared governance metadata).
* Reflection content — included (declared agent reasoning; the whole point of
  the capability is to make cognition observable).

Four capabilities:

* ``planning.create_plan``  — declare a plan with ordered steps; emits plan_created
* ``planning.step_update``  — record step started / completed / failed
* ``planning.revise``       — record a plan revision with optional added steps
* ``planning.reflect``      — record a structured reflection with optional score
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability
from chp_core.types import (
    EvaluationResult,
    PlanDescriptor,
    PlanStep,
    new_id,
)


@dataclass
class PlanningConfig:
    """Configuration for PlanningAdapter (currently stateless; reserved for future use)."""


class PlanningAdapter(BaseAdapter):
    """Observable agent cognition — planning and reflection as governed capabilities."""

    def __init__(self, config: PlanningConfig | None = None) -> None:
        self._config = config or PlanningConfig()

    @capability(
        id="chp.adapters.planning.create_plan",
        emits=['plan_created'],
        version="0.1.0",
        category="agent_operations",
        risk="medium",
        description=(
            "Declare an agent plan: intent + ordered steps. "
            "Emits plan_created evidence. Returns the full PlanDescriptor."
        ),
        input_schema={
            "type": "object",
            "required": ["intent"],
            "properties": {
                "plan_id": {
                    "type": "string",
                    "description": "Stable plan identifier; auto-generated if omitted.",
                },
                "intent": {"type": "string", "minLength": 1},
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["step_id", "description"],
                        "properties": {
                            "step_id": {"type": "string"},
                            "description": {"type": "string"},
                            "capability_id": {"type": ["string", "null"]},
                        },
                        "additionalProperties": False,
                    },
                    "default": [],
                },
                "parent_correlation_id": {"type": "string"},
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
    )
    async def create_plan(self, ctx: Any, payload: dict) -> dict:
        plan_id = payload.get("plan_id") or new_id("plan")
        intent = payload["intent"]
        raw_steps = payload.get("steps") or []
        steps = [
            PlanStep(
                step_id=s["step_id"],
                description=s["description"],
                capability_id=s.get("capability_id"),
            )
            for s in raw_steps
        ]
        descriptor = PlanDescriptor(
            plan_id=plan_id,
            intent=intent,
            steps=steps,
            parent_correlation_id=payload.get("parent_correlation_id"),
            metadata=dict(payload.get("metadata") or {}),
        )
        ctx.emit("plan_created", {
            "plan_id": plan_id,
            "intent": intent,
            "step_count": len(steps),
            "steps": [
                {"step_id": s.step_id, "description": s.description}
                for s in steps
            ],
        })
        return descriptor.to_dict()

    @capability(
        id="chp.adapters.planning.step_update",
        version="0.1.0",
        category="agent_operations",
        risk="low",
        description=(
            "Record a plan step transition: started → completed or failed. "
            "Emits plan_step_started or plan_step_completed."
        ),
        input_schema={
            "type": "object",
            "required": ["plan_id", "step_id", "status"],
            "properties": {
                "plan_id": {"type": "string"},
                "step_id": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": ["started", "completed", "failed"],
                },
                "result": {
                    "type": "object",
                    "description": "Structured result (for status=completed).",
                },
                "error": {
                    "type": "string",
                    "description": "Error message (for status=failed).",
                },
            },
            "additionalProperties": False,
        },
    )
    async def step_update(self, ctx: Any, payload: dict) -> dict:
        plan_id = payload["plan_id"]
        step_id = payload["step_id"]
        status = payload["status"]

        if status == "started":
            ctx.emit("plan_step_started", {"plan_id": plan_id, "step_id": step_id})
        else:
            ev: dict[str, Any] = {
                "plan_id": plan_id,
                "step_id": step_id,
                "status": status,
            }
            if status == "completed" and (result := payload.get("result")):
                ev["result"] = result
            if status == "failed" and (error := payload.get("error")):
                ev["error"] = error
            ctx.emit("plan_step_completed", ev)

        return {"plan_id": plan_id, "step_id": step_id, "status": status}

    @capability(
        id="chp.adapters.planning.revise",
        version="0.1.0",
        category="agent_operations",
        risk="medium",
        description=(
            "Record a plan revision: why it changed and any added steps. "
            "Emits plan_revised evidence."
        ),
        input_schema={
            "type": "object",
            "required": ["plan_id", "reason"],
            "properties": {
                "plan_id": {"type": "string"},
                "reason": {"type": "string", "minLength": 1},
                "added_steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["step_id", "description"],
                        "properties": {
                            "step_id": {"type": "string"},
                            "description": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                    "default": [],
                },
            },
            "additionalProperties": False,
        },
    )
    async def revise(self, ctx: Any, payload: dict) -> dict:
        plan_id = payload["plan_id"]
        reason = payload["reason"]
        added_steps = payload.get("added_steps") or []
        ctx.emit("plan_revised", {
            "plan_id": plan_id,
            "reason": reason,
            "added_step_count": len(added_steps),
            "added_steps": [
                {"step_id": s["step_id"], "description": s["description"]}
                for s in added_steps
            ],
        })
        return {"plan_id": plan_id, "added_step_count": len(added_steps)}

    @capability(
        id="chp.adapters.planning.reflect",
        version="0.1.0",
        category="agent_operations",
        risk="low",
        description=(
            "Record a structured reflection. Emits reflection_started, "
            "outcome_scored (if score provided), and reflection_completed."
        ),
        input_schema={
            "type": "object",
            "required": ["subject", "content"],
            "properties": {
                "subject": {"type": "string", "minLength": 1},
                "content": {"type": "string"},
                "score": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "Normalised evaluation score 0–1.",
                },
                "rubric": {"type": "string"},
                "evaluator": {
                    "type": "string",
                    "description": "'model' | 'human' | 'automated'",
                    "default": "model",
                },
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Event IDs cited by this evaluation.",
                },
            },
            "additionalProperties": False,
        },
    )
    async def reflect(self, ctx: Any, payload: dict) -> dict:
        subject = payload["subject"]
        content = payload["content"]
        score = payload.get("score")
        rubric = payload.get("rubric", "")
        evaluator = payload.get("evaluator", "model")
        evidence_refs = list(payload.get("evidence_refs") or [])

        ctx.emit("reflection_started", {"subject": subject})

        if score is not None:
            evaluation = EvaluationResult(
                score=score,
                rubric=rubric,
                evaluator=evaluator,
                evidence_refs=evidence_refs,
            )
            ctx.emit("outcome_scored", {"subject": subject, **evaluation.to_dict()})

        ctx.emit("reflection_completed", {
            "subject": subject,
            "content": content,
            "content_parts": 1,
        })

        return {
            "subject": subject,
            "content_parts": 1,
            "scored": score is not None,
        }
