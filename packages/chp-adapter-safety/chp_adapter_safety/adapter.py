"""SafetyAdapter — risk assessment and guardrail evaluation as CHP capabilities.

Evidence hygiene:
* capability_id, level, score, recommendation — all in evidence.
* payload hash — in evidence for report; raw payload — NEVER in evidence.
* block_reason string — in evidence (governance transparency).

Two capabilities:

* ``safety.assess``  — quick risk score for a capability + payload; emits
                       safety_assessment_started/completed + blocked/approved
* ``safety.report``  — full report with guardrail evaluation; same event chain
                       plus safety_guardrail_triggered when a rule fires
"""
from __future__ import annotations

from dataclasses import dataclass, field

from chp_core import BaseAdapter, capability
from chp_core.safety import RuleBasedSafetyEvaluator
from chp_core.types import GuardrailDefinition


@dataclass
class SafetyConfig:
    """Inject a pre-configured evaluator and/or extra guardrail rules."""

    evaluator: RuleBasedSafetyEvaluator | None = None
    guardrails: list[GuardrailDefinition] = field(default_factory=list)

    def effective_evaluator(self) -> RuleBasedSafetyEvaluator:
        ev = (
            self.evaluator
            if self.evaluator is not None
            else RuleBasedSafetyEvaluator()
        )
        for g in self.guardrails:
            ev.register_guardrail(g)
        return ev


class SafetyAdapter(BaseAdapter):
    """Risk assessment and guardrail evaluation as governed capabilities."""

    def __init__(self, config: SafetyConfig | None = None) -> None:
        self._config = config or SafetyConfig()
        self._evaluator = self._config.effective_evaluator()

    @capability(
        id="chp.adapters.safety.assess",
        emits=['safety_action_approved', 'safety_action_blocked', 'safety_assessment_completed', 'safety_assessment_started'],
        version="0.1.0",
        category="governance",
        risk="low",
        description=(
            "Score the risk level of any capability invocation and emit a "
            "safety_action_approved or safety_action_blocked event."
        ),
        input_schema={
            "type": "object",
            "required": ["capability_id"],
            "properties": {
                "capability_id": {
                    "type": "string",
                    "description": "The capability being evaluated.",
                },
                "payload": {
                    "type": "object",
                    "description": "The invocation payload to scan for risk keywords.",
                },
            },
            "additionalProperties": False,
        },
    )
    async def assess(self, ctx, payload: dict) -> dict:
        cap_id = payload["capability_id"]
        invoke_payload = dict(payload.get("payload") or {})

        ctx.emit("safety_assessment_started", {"capability_id": cap_id})
        assessment = self._evaluator.assess(cap_id, invoke_payload)
        ctx.emit("safety_assessment_completed", {
            "capability_id": cap_id,
            "level": assessment.level,
            "score": assessment.score,
            "recommendation": assessment.recommendation,
        })
        if assessment.recommendation == "block":
            ctx.emit("safety_action_blocked", {
                "capability_id": cap_id,
                "level": assessment.level,
            })
        else:
            ctx.emit("safety_action_approved", {
                "capability_id": cap_id,
                "recommendation": assessment.recommendation,
            })
        return assessment.to_dict()

    @capability(
        id="chp.adapters.safety.report",
        version="0.1.0",
        category="governance",
        risk="medium",
        description=(
            "Full safety report: risk score + guardrail evaluation. "
            "Emits safety_guardrail_triggered when a rule fires."
        ),
        input_schema={
            "type": "object",
            "required": ["capability_id"],
            "properties": {
                "capability_id": {
                    "type": "string",
                    "description": "The capability being evaluated.",
                },
                "payload": {
                    "type": "object",
                    "description": "The invocation payload (hashed for evidence; not stored raw).",
                },
            },
            "additionalProperties": False,
        },
    )
    async def report(self, ctx, payload: dict) -> dict:
        cap_id = payload["capability_id"]
        invoke_payload = dict(payload.get("payload") or {})

        ctx.emit("safety_assessment_started", {"capability_id": cap_id})
        safety_report = self._evaluator.report(cap_id, invoke_payload)
        ctx.emit("safety_assessment_completed", {
            "capability_id": cap_id,
            "level": safety_report.assessment.level,
            "approved": safety_report.approved,
        })
        if safety_report.approved:
            ctx.emit("safety_action_approved", {"capability_id": cap_id})
        else:
            ctx.emit("safety_guardrail_triggered", {
                "capability_id": cap_id,
                "reason": safety_report.block_reason,
            })
            ctx.emit("safety_action_blocked", {
                "capability_id": cap_id,
                "reason": safety_report.block_reason,
            })
        return safety_report.to_dict()
