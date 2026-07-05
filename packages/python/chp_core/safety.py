"""Risk evaluation and guardrail capability for CHP.

Risk-tier semantics and the safety event vocabulary are normative in
spec/chp-governance-v0.2.md §3–§4.2.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    GuardrailDefinition,
    RiskAssessment,
    RiskLevel,
    SafetyReport,
    new_id,
    utc_now,
)

_SAFETY_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "safety_assessment_started",
    "safety_assessment_completed",
    "safety_guardrail_triggered",
    "safety_action_blocked",
    "safety_action_approved",
]

_HIGH_RISK_CAP_PATTERNS = [
    # NOTE: these match capability IDs (not shell text), so keep them specific. "*rm*" was removed —
    # it false-matched "confo[rm]ance" (and "transform", etc.); the `rm -rf` shell command is caught by
    # *bash*/*shell* on cap ids and the critical "rm -rf" payload keyword instead.
    "*bash*", "*exec*", "*shell*", "*delete*", "*drop*", "*destroy*",
    # Secrets + arbitrary subprocess/container execution (safety.assess previously rated these "allow").
    "*secrets.set*", "*secrets.delete*", "*process.run*", "*process.exec*", "*process.spawn*",
    "*container.run*", "*container.exec*",
    # Mesh control actions: remote update/restart/stop/install on a node's runtime.
    "*host.update*", "*host.restart*", "*host.stop*", "*host.install_adapter*",
    "*launchd.start*", "*launchd.stop*", "*launchd.install*", "*launchd.uninstall*",
    # Inference-server lifecycle: spawning/killing model servers.
    "*start_server*", "*stop_server*",
]
_MEDIUM_RISK_CAP_PATTERNS = [
    "*write*", "*create*", "*update*", "*post*", "*put*", "*patch*",
]
_RISK_KEYWORDS: dict[RiskLevel, list[str]] = {
    "critical": ["rm -rf", "drop table", "delete from", "format", "shutdown"],
    "high": ["sudo", "chmod", "kill", "overwrite", "truncate"],
    "medium": ["write", "create", "update", "modify"],
}
_LEVEL_TO_SCORE: dict[RiskLevel, float] = {
    "low": 0.1,
    "medium": 0.4,
    "high": 0.7,
    "critical": 0.95,
}
_LEVEL_ORDER: list[RiskLevel] = ["low", "medium", "high", "critical"]


def _level_from_score(score: float) -> RiskLevel:
    if score >= 0.8:
        return "critical"
    if score >= 0.55:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def _recommendation(level: RiskLevel) -> str:
    return {
        "low": "allow",
        "medium": "warn",
        "high": "require_approval",
        "critical": "block",
    }[level]


class RuleBasedSafetyEvaluator:
    """Keyword and pattern-based risk scorer with configurable guardrail chains."""

    def __init__(
        self,
        guardrails: list[GuardrailDefinition] | None = None,
        *,
        high_risk_cap_patterns: list[str] | None = None,
    ) -> None:
        self._guardrails: list[GuardrailDefinition] = list(guardrails or [])
        self._high_risk_cap_patterns = high_risk_cap_patterns or list(_HIGH_RISK_CAP_PATTERNS)

    def register_guardrail(self, guardrail: GuardrailDefinition) -> None:
        self._guardrails.append(guardrail)

    def assess(self, capability_id: str, payload: dict) -> RiskAssessment:
        score = 0.0
        factors: list[str] = []

        cap_lower = capability_id.lower()
        for pattern in self._high_risk_cap_patterns:
            if fnmatch.fnmatch(cap_lower, pattern.lower()):
                new_score = _LEVEL_TO_SCORE["high"]
                if new_score > score:
                    score = new_score
                    factors.append(f"capability matches high-risk pattern '{pattern}'")
                break

        if score < _LEVEL_TO_SCORE["medium"]:
            for pattern in _MEDIUM_RISK_CAP_PATTERNS:
                if fnmatch.fnmatch(cap_lower, pattern.lower()):
                    new_score = _LEVEL_TO_SCORE["medium"]
                    if new_score > score:
                        score = new_score
                        factors.append("capability matches medium-risk pattern")
                    break

        payload_text = json.dumps(payload, sort_keys=True).lower()
        for level in ("critical", "high", "medium"):
            for kw in _RISK_KEYWORDS[level]:  # type: ignore[index]
                if kw in payload_text:
                    kw_score = _LEVEL_TO_SCORE[level]  # type: ignore[index]
                    if kw_score > score:
                        score = kw_score
                        factors.append(f"payload contains keyword '{kw}'")
                    break

        score = min(score, 1.0)
        level = _level_from_score(score)
        return RiskAssessment(
            level=level,
            score=round(score, 3),
            factors=factors or ["no risk factors detected"],
            recommendation=_recommendation(level),  # type: ignore[arg-type]
            assessed_at=utc_now(),
        )

    def evaluate_guardrails(
        self, capability_id: str, assessment: RiskAssessment
    ) -> tuple[bool, str | None, list[str]]:
        """Return (approved, block_reason, evaluated_guardrail_ids)."""
        evaluated: list[str] = []
        for g in self._guardrails:
            if not fnmatch.fnmatch(capability_id, g.capability_id_pattern):
                continue
            evaluated.append(g.id)
            if _LEVEL_ORDER.index(assessment.level) > _LEVEL_ORDER.index(g.max_risk_level):
                return (
                    False,
                    f"guardrail '{g.id}': risk level {assessment.level!r} exceeds max {g.max_risk_level!r}",
                    evaluated,
                )
            if capability_id in g.requires_human_for:
                return (
                    False,
                    f"guardrail '{g.id}': '{capability_id}' requires human approval",
                    evaluated,
                )
        return True, None, evaluated

    def report(self, capability_id: str, payload: dict) -> SafetyReport:
        assessment = self.assess(capability_id, payload)
        approved, block_reason, evaluated = self.evaluate_guardrails(capability_id, assessment)
        payload_hash = "sha256:" + hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        return SafetyReport(
            report_id=new_id("sr"),
            capability_id=capability_id,
            payload_hash=payload_hash,
            assessment=assessment,
            guardrails_evaluated=evaluated,
            approved=approved,
            block_reason=block_reason,
            generated_at=utc_now(),
        )


def register_safety_capability(
    host: Any,
    evaluator: RuleBasedSafetyEvaluator | None = None,
) -> None:
    evaluator = evaluator or RuleBasedSafetyEvaluator()

    assess_desc = CapabilityDescriptor(
        id="safety.assess",
        version="1.0.0",
        description="Assess the risk level of a capability invocation.",
        category=CapabilityCategory.GOVERNANCE,
        tags=["safety", "risk"],
        emits=list(_SAFETY_EMITS),
    )

    report_desc = CapabilityDescriptor(
        id="safety.report",
        version="1.0.0",
        description="Generate a full safety report including guardrail evaluation.",
        category=CapabilityCategory.GOVERNANCE,
        tags=["safety", "compliance"],
        emits=list(_SAFETY_EMITS),
    )

    async def _assess(ctx, payload) -> dict:
        capability_id = str(payload.get("capability_id") or "")
        invoke_payload = dict(payload.get("payload") or {})

        ctx.emit("safety_assessment_started", {"capability_id": capability_id}, redacted=False)
        assessment = evaluator.assess(capability_id, invoke_payload)
        ctx.emit(
            "safety_assessment_completed",
            {
                "capability_id": capability_id,
                "level": assessment.level,
                "score": assessment.score,
                "recommendation": assessment.recommendation,
            },
            redacted=False,
        )
        if assessment.recommendation == "block":
            ctx.emit(
                "safety_action_blocked",
                {"capability_id": capability_id, "level": assessment.level},
                redacted=False,
            )
        else:
            ctx.emit(
                "safety_action_approved",
                {"capability_id": capability_id, "recommendation": assessment.recommendation},
                redacted=False,
            )
        return assessment.to_dict()

    async def _report(ctx, payload) -> dict:
        capability_id = str(payload.get("capability_id") or "")
        invoke_payload = dict(payload.get("payload") or {})

        ctx.emit("safety_assessment_started", {"capability_id": capability_id}, redacted=False)
        safety_report = evaluator.report(capability_id, invoke_payload)
        ctx.emit(
            "safety_assessment_completed",
            {
                "capability_id": capability_id,
                "level": safety_report.assessment.level,
                "approved": safety_report.approved,
            },
            redacted=False,
        )
        if safety_report.approved:
            ctx.emit(
                "safety_action_approved",
                {"capability_id": capability_id},
                redacted=False,
            )
        else:
            ctx.emit(
                "safety_guardrail_triggered",
                {"capability_id": capability_id, "reason": safety_report.block_reason},
                redacted=False,
            )
            ctx.emit(
                "safety_action_blocked",
                {"capability_id": capability_id, "reason": safety_report.block_reason},
                redacted=False,
            )
        return safety_report.to_dict()

    host.register(assess_desc, _assess)
    host.register(report_desc, _report)
