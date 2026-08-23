"""Readiness kernel — ReadinessAssessment + VerificationPlan (proposal 0044, Tier B).

Readiness is DERIVED and CONTEXTUAL, never a permanent entity boolean (CHP-RDY-001,
CHP-ENT-007): it is assessed for an entity toward a specific capability/binding in a specific
market, derived from per-requirement four-state results (each citing the assertions +
verification_results that produced it, CHP-RDY-002), and expiry-bound (CHP-RDY-004). A
requirement returning unknown/error → incomplete, never silently eligible (CHP-RDY-007).
Historical assessments are immutable; re-evaluation creates a new record (CHP-RDY-005/008).

Readiness NEVER implies admission (CHP-RDY-003) — admission (0043) is a separate, later step.

A VerificationPlan projects what evidence is STILL outstanding, so a surface can explain why
readiness is incomplete rather than show a generic progress bar (CHP-RDY-010).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, new_id, utc_now

# ONB-006: remediation metadata that is not yet known is EXPLICITLY "unknown", never silently 0 or
# absent — so a surface distinguishes "free / instant / always-available" from "not yet known".
UNKNOWN = "unknown"


def plan_item(
    requirement_id: str,
    claim_type: str,
    acceptable_evidence: list[str],
    *,
    completion: str = "outstanding",
    verifier: JSON | None = None,
    disclosed_fields: list[str] | None = None,
    cost: str = UNKNOWN,
    latency: str = UNKNOWN,
    availability: str = UNKNOWN,
) -> JSON:
    """Build one outstanding VerificationPlan item (proposal 0044; CHP-ONB-003/004/005/006).

    acceptable_evidence names what would satisfy the item (ONB-003, MUST name >=1). Remediation
    metadata (cost/latency/availability) is ALWAYS present and defaults to the explicit UNKNOWN
    sentinel (ONB-006) — never silently 0 — so "not yet known" is representable and distinct from a
    real value. verifier (ONB-004, MAY) names an evidence-producing capability; disclosed_fields
    (ONB-005, SHOULD) names the fields a disclosure item would reveal."""
    if not acceptable_evidence:
        raise ValueError("a VerificationPlan item MUST name >=1 acceptable evidence (CHP-ONB-003)")
    item: JSON = {
        "requirement_id": requirement_id,
        "claim_type": claim_type,
        "acceptable_evidence": list(acceptable_evidence),
        "completion": completion,
        "cost": cost,
        "latency": latency,
        "availability": availability,
    }
    if verifier is not None:
        item["verifier"] = verifier
    if disclosed_fields:
        item["disclosed_fields"] = list(disclosed_fields)
    return item


@dataclass(slots=True, frozen=True)
class ReadinessAssessment:
    """Derived, contextual readiness. See module docstring for the invariants.

    FROZEN (CHP-RDY-008): a historical assessment is immutable — it can never be rewritten in
    place. Re-evaluation (CHP-RDY-005) constructs a NEW assessment (fresh id + evaluated_at),
    leaving the prior record unchanged; a relying store appends, never mutates."""

    subject: JSON  # {entity, capability, binding, market} — readiness is per-context
    profile: JSON  # {id, version}
    requirements: list[JSON]  # [{id, result(four-state), assertions?, verification_results?, details?}]
    result: str  # eligible | ineligible | incomplete | stale | suspended
    id: str = field(default_factory=lambda: new_id("rdy"))
    evaluated_at: str = field(default_factory=utc_now)
    valid_until: str | None = None

    RESULTS: ClassVar[frozenset[str]] = frozenset(
        {"eligible", "ineligible", "incomplete", "stale", "suspended"}
    )

    def __post_init__(self) -> None:
        if self.result not in self.RESULTS:
            raise ValueError(f"readiness result must be one of {sorted(self.RESULTS)}")

    @staticmethod
    def derive_result(
        requirements: list[JSON], *, suspended: bool = False, stale: bool = False
    ) -> str:
        """Derive readiness from per-requirement four-state results. NEVER 'eligible' unless
        EVERY requirement is satisfied (CHP-RDY-007): an unsatisfied requirement → ineligible;
        an unknown/error requirement (and no unsatisfied) → incomplete; none → incomplete.
        suspended (entity status) and stale (past validity) are overrides that dominate."""
        if suspended:
            return "suspended"
        if stale:
            return "stale"
        vals = {r.get("result") for r in requirements}
        if "unsatisfied" in vals:
            return "ineligible"
        if "unknown" in vals or "error" in vals or not requirements:
            return "incomplete"
        return "eligible"

    def is_eligible(self) -> bool:
        """Eligible for this context — NOT admitted (CHP-RDY-003). Admission is a later step."""
        return self.result == "eligible"

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.valid_until is None:
            data.pop("valid_until", None)
        return data


@dataclass(slots=True)
class VerificationPlan:
    """The projection of evidence STILL outstanding for a readiness/requirement target
    (proposal 0044; CHP-RDY-010) — what is missing, the acceptable evidence, and completion,
    so a surface explains WHY readiness is incomplete instead of a generic progress bar."""

    target: JSON  # what this plan is for, e.g. {entity, capability}
    profile: JSON  # {id, version}
    outstanding: list[JSON]  # [{requirement_id, claim_type, acceptable_evidence[], completion}]
    # ONB-007: the assessment this plan remediates, so an unsatisfied readiness traces to its plan.
    assessment_id: str | None = None
    id: str = field(default_factory=lambda: new_id("vplan"))
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.assessment_id is None:
            data.pop("assessment_id", None)
        return data

    @classmethod
    def from_assessment(cls, assessment: ReadinessAssessment, unmet: list[JSON]) -> "VerificationPlan":
        """Build the plan for the not-yet-satisfied requirements of an incomplete assessment. The
        plan back-references the assessment id (CHP-ONB-007) so remediation is traceable to it."""
        return cls(
            target=assessment.subject,
            profile=assessment.profile,
            outstanding=list(unmet),
            assessment_id=assessment.id,
        )
