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

import hashlib
import re
from dataclasses import dataclass, field

from chp_core import BaseAdapter, capability
from chp_core.safety import RuleBasedSafetyEvaluator
from chp_core.types import GuardrailDefinition

# Prompt-injection / jailbreak heuristics (OWASP LLM01). Category → compiled patterns. Heuristic v1 —
# catches the common signatures in untrusted content; a model-based classifier is the upgrade path.
_INJECTION_PATTERNS: dict[str, list[re.Pattern]] = {
    "instruction_override": [re.compile(p, re.I) for p in (
        r"ignore\s+(all\s+|the\s+|your\s+)?(previous|prior|above|earlier)",
        r"disregard\s+(the|all|any|previous|above)",
        r"forget\s+(everything|the\s+above|all\s+previous|your\s+(instructions|rules))",
        r"\bnew\s+instructions?\s*:", r"override\s+(the\s+)?(system|previous)")],
    "role_manipulation": [re.compile(p, re.I) for p in (
        r"you\s+are\s+now\b", r"\bact\s+as\b", r"pretend\s+(to\s+be|you\s+are)",
        r"developer\s+mode", r"\bDAN\b", r"\bjailbreak", r"do\s+anything\s+now")],
    "system_prompt_leak": [re.compile(p, re.I) for p in (
        r"(reveal|print|repeat|show|output|tell\s+me)\b.{0,25}\b(system|your)\s+(prompt|instructions?|rules)",
        r"repeat\s+the\s+(words|text|instructions)\s+above", r"what\s+(are|were)\s+your\s+(instructions|rules|prompt)")],
    "action_hijack": [re.compile(p, re.I) for p in (
        r"</?(system|assistant|tool|instructions?)>", r"```\s*system",
        r"(send|email|delete|remove|transfer|exfiltrate|execute|run)\b.{0,40}\b(to|the|command|file|password|secret|key)")],
}


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

    @capability(
        id="chp.adapters.safety.scan_injection",
        version="0.1.0",
        emits=["safety_injection_scanned", "safety_injection_detected"],
        category="governance",
        risk="low",
        description=(
            "Scan untrusted content (a prompt, tool result, or retrieved document) for prompt-injection / "
            "jailbreak signatures (OWASP LLM01) — instruction-override, role/system manipulation, system-prompt "
            "exfiltration, embedded action-hijack — and emit a SIGNED verdict {injection_detected, risk 0-1, "
            "categories, recommendation: allow|flag|block}. The tamper-evident guardrail decision is the CHP "
            "edge; pairs with eval.action_gate (structure) as the pre-execution guardrail layer. Redacted: the "
            "raw text is never emitted, only its sha256 + matched categories + risk. Heuristic v1 — a "
            "model-based classifier is the upgrade path."
        ),
        input_schema={
            "type": "object",
            "required": ["text"],
            "properties": {
                "text": {"type": "string", "description": "Untrusted content to scan. Hashed for evidence, never emitted raw."},
                "source": {"type": "string", "description": "Provenance of the text (user | tool | retrieval | web) — informational."},
                "block_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0, "description": "risk >= this → recommendation 'block' (default 0.5)."},
                "flag_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0, "description": "risk >= this → 'flag' (default 0.25)."},
            },
            "additionalProperties": False,
        },
    )
    async def scan_injection(self, ctx, payload: dict) -> dict:
        text = payload["text"] or ""
        source = payload.get("source")
        block_t = float(payload.get("block_threshold", 0.5))
        flag_t = float(payload.get("flag_threshold", 0.25))
        text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()

        categories: dict[str, int] = {}
        total = 0
        for cat, pats in _INJECTION_PATTERNS.items():
            hits = sum(1 for p in pats if p.search(text))
            if hits:
                categories[cat] = hits
                total += hits
        # risk: each distinct category is a strong independent signal; 3+ categories → 1.0, +0.1 if many hits.
        risk = round(min(1.0, len(categories) / 3.0 + (0.1 if total > 3 else 0.0)), 4) if categories else 0.0
        detected = bool(categories)
        recommendation = "block" if risk >= block_t else ("flag" if risk >= flag_t else "allow")

        ctx.emit("safety_injection_scanned", {
            "source": source, "text_sha256": text_sha256, "risk": risk,
            "categories": sorted(categories), "recommendation": recommendation}, redacted=False)
        if detected:
            ctx.emit("safety_injection_detected", {
                "source": source, "text_sha256": text_sha256, "risk": risk,
                "categories": sorted(categories)}, redacted=False)
        return {
            "injection_detected": detected, "risk": risk, "categories": categories,
            "recommendation": recommendation, "text_sha256": text_sha256, "source": source,
        }
