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

    @capability(
        id="chp.adapters.safety.verify_tpm_witness",
        version="1.0.0",
        description=(
            "Verify a TPM witness attestation and derive its witness-independence class (W0–W4), "
            "producer-independent — the verifier re-derives every condition and trusts no boolean the "
            "collector asserted: the W3-base Ed25519 attestation (signature / host-distinctness / "
            "bundle-digest match / integrity re-verification / trusted key), the TPM quote signature "
            "under the AK, the quote's extraData == the attested bundle digest, and the EK certificate "
            "chaining to a PINNED manufacturer root bundled with this adapter (Intel OnDie CA). Returns "
            "W4_HARDWARE_ATTESTED only when all hold; otherwise it stays at the verified base (≤ W3) — "
            "a software/self-signed TPM cannot forge W4. Pure verification (optional AIA fetch of "
            "intermediate CA certs, offline-tolerant)."
        ),
        category="attestation",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "attestation": {"type": "object",
                                "description": "TPM witness attestation: W3-base Ed25519 fields "
                                               "(witness_host/witness_key_id/witness_pubkey_hex/"
                                               "bundle_sha256/integrity_reverified/signature) + a `tpm` "
                                               "block (quote_message_b64/quote_signature_b64/"
                                               "ak_public_b64/ek_certificate_der_b64/issuer_chain_der_b64)."},
                "expected_bundle_sha256": {"type": "string",
                                           "description": "sha256:<hex> digest the witness must attest."},
                "producer_host": {"type": "string",
                                  "description": "the bundle's producer host (must differ from the witness host)."},
                "trusted_witness_keys": {"type": "object",
                                         "additionalProperties": {"type": "string"},
                                         "description": "map witness key_id -> public-key hex of keys known "
                                                        "to belong to independent hosts (anchored out of band)."},
                "allow_network": {"type": "boolean",
                                  "description": "follow AIA to fetch intermediate CA certs (default true).",
                                  "default": True},
            },
            "required": ["attestation", "expected_bundle_sha256", "producer_host"],
            "additionalProperties": False,
        },
        emits=["safety_witness_verified", "safety_witness_error"],
        tags=["safety", "attestation", "witness", "tpm", "hardware"],
    )
    async def verify_tpm_witness(self, ctx, payload: dict) -> dict:
        from ._tpm_witness import WitnessIndependence, verify_tpm_witness as _verify

        att = payload.get("attestation")
        if not isinstance(att, dict):
            ctx.emit("safety_witness_error", {"reason": "attestation_not_an_object"}, redacted=False)
            raise ValueError("verify_tpm_witness: 'attestation' must be an object")
        expected = str(payload["expected_bundle_sha256"])
        v = _verify(
            att, expected_bundle_sha256=expected, producer_host=str(payload["producer_host"]),
            trusted_witness_keys=payload.get("trusted_witness_keys") or {},
            allow_network=payload.get("allow_network", True) is not False)
        d = v.derivation
        result = {
            "witness_class": d.independence.name,
            "witness_class_rank": int(d.independence),
            "hardware_attested": d.independence == WitnessIndependence.W4_HARDWARE_ATTESTED,
            "quote_present": v.quote_present,
            "quote_signature_valid": v.quote_signature_valid,
            "qualifying_data": v.qualifying_data,
            "qualifying_matches_bundle": v.qualifying_data == expected,
            "ek_chain_verified": v.ek_chain_verified,
            "ek_chain_notes": list(v.ek_chain_notes),
            "reasons": list(d.reasons),
            "base_reasons": list(v.base_reasons),
        }
        ctx.emit("safety_witness_verified", {
            "witness_class": result["witness_class"], "ek_chain_verified": v.ek_chain_verified,
            "quote_signature_valid": v.quote_signature_valid}, redacted=False)
        return result

    @capability(
        id="chp.adapters.safety.tpm_witness_attest",
        version="1.0.0",
        description=(
            "Produce a TPM witness attestation over a Safety Case bundle, running ON the invoking host "
            "(the COLLECTOR half; the sibling of verify_tpm_witness). Re-verifies the bundle's integrity, "
            "signs a W3-base attestation with a host-held Ed25519 key, and runs the TPM2 quote ceremony "
            "(createek/getekcertificate/createak/quote with the bundle digest as qualifying data) + reads "
            "the EK issuer chain from TPM NV. Asserts NOTHING about W4 — it only collects; "
            "verify_tpm_witness derives the class. Fail-closed: no TPM / ceremony failure still returns "
            "the signed W3-base attestation with tpm.available=false. Needs the host's tpm2-tools."
        ),
        category="attestation",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "bundle_b64": {"type": "string",
                               "description": "base64 of the .chpsafety bundle bytes to witness."},
                "execution_id": {"type": "string",
                                 "description": "correlates the attestation to an execution (default auto)."},
                "pcrs": {"type": "string", "description": "PCR selection for the quote (default sha256:0-7)."},
                "ek_alg": {"type": "string", "enum": ["rsa", "ecc"],
                           "description": "EK/AK asymmetric algorithm (default rsa)."},
            },
            "required": ["bundle_b64"],
            "additionalProperties": False,
        },
        emits=["safety_witness_attested", "safety_witness_error"],
        tags=["safety", "attestation", "witness", "tpm", "hardware"],
    )
    async def tpm_witness_attest(self, ctx, payload: dict) -> dict:
        import base64 as _b64
        from ._tpm_collector import build_attestation

        b64 = payload.get("bundle_b64")
        if not isinstance(b64, str) or not b64:
            ctx.emit("safety_witness_error", {"reason": "bundle_b64_missing"}, redacted=False)
            raise ValueError("tpm_witness_attest: 'bundle_b64' (base64 of the bundle) is required")
        try:
            bundle = _b64.b64decode(b64)
        except Exception as exc:  # noqa: BLE001
            ctx.emit("safety_witness_error", {"reason": "bundle_b64_not_decodable"}, redacted=False)
            raise ValueError(f"tpm_witness_attest: bundle_b64 is not valid base64: {exc}") from exc

        execution_id = payload.get("execution_id")
        if not execution_id:
            import time as _t
            execution_id = f"tpm-witness-{int(_t.time())}"
        att = build_attestation(
            bundle, execution_id=execution_id,
            pcrs=str(payload.get("pcrs") or "sha256:0,1,2,3,4,5,6,7"),
            ek_alg=str(payload.get("ek_alg") or "rsa"))
        tpm = att.get("tpm", {})
        ctx.emit("safety_witness_attested", {
            "bundle_sha256": att.get("bundle_sha256"), "witness_host": att.get("witness_host"),
            "tpm_available": bool(tpm.get("available")), "integrity_reverified": att.get("integrity_reverified"),
        }, redacted=False)
        return {
            "attestation": att,
            "bundle_sha256": att.get("bundle_sha256"),
            "witness_host": att.get("witness_host"),
            "tpm_available": bool(tpm.get("available")),
            "tpm_error": tpm.get("error"),
            "integrity_reverified": att.get("integrity_reverified"),
        }

    @capability(
        id="chp.adapters.safety.verify_containment",
        version="1.0.0",
        description=(
            "Producer-independent check that a running OpenCell cell satisfies its Envelope-required "
            "containment invariants. Input an INDEPENDENT observation of the cell (not the control "
            "plane that made it) + the compiled plan constraints + the asserted boundary class; output "
            "a fail-closed verdict (satisfied + per-failure reasons). Checks: no guest vNIC, non-root, "
            "no guest-visible credentials, read-only rootfs when required, authenticated effect channel, "
            "network mode matches, and the live runtime matches the pinned boundary runtime (so a "
            "gVisor/microVM plan run on plain runc fails closed). Pure — no docker/host side effects."
        ),
        category="containment",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "observation": {"type": "object",
                                "description": "independent cell observation: guest_network_device / "
                                               "non_root_user / guest_credentials / read_only_rootfs / "
                                               "effect_channel / channel_authenticated / network_mode / runtime."},
                "constraints": {"type": "object",
                                "description": "compiled plan constraints: network / read_only / docker_runtime."},
                "boundary_class": {"type": "string",
                                   "description": "asserted boundary class (e.g. microvm, gvisor-sandbox-kernel)."},
            },
            "required": ["observation", "constraints"],
            "additionalProperties": False,
        },
        emits=["safety_containment_verified"],
        tags=["safety", "containment", "opencell", "verifier"],
    )
    async def verify_containment(self, ctx, payload: dict) -> dict:
        from ._containment import verify_cell_against_plan

        obs = payload.get("observation")
        cons = payload.get("constraints")
        if not isinstance(obs, dict) or not isinstance(cons, dict):
            ctx.emit("safety_containment_verified", {"satisfied": False, "reason": "bad_input"}, redacted=False)
            raise ValueError("verify_containment: 'observation' and 'constraints' must be objects")
        bc = str(payload.get("boundary_class") or "")
        satisfied, failures = verify_cell_against_plan(obs, cons, boundary_class=bc)
        ctx.emit("safety_containment_verified",
                 {"satisfied": satisfied, "boundary_class": bc, "failure_count": len(failures)},
                 redacted=False)
        return {"satisfied": satisfied, "failures": failures, "boundary_class": bc, "observed": dict(obs)}
