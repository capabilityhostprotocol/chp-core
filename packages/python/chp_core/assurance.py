"""Assurance vector — the multi-dimensional assurance of a claim, PRESERVED (CHP-TRUST-004).

Assurance is not one number. A claim can be integrity-verified yet from an unauthorized issuer, fresh
yet uncorroborated, executor-complete yet effect-unconfirmed. TRUST-004 requires those dimensions be
kept SEPARATE rather than collapsed into a single normative scalar. AssuranceVector is a pure
PROJECTION that carries the dimensions that already exist as evidence — VerificationResult's per-check
four-states, the effect determination, the independent-corroboration count, the issuer-authority trust
decision — TOGETHER, so a consumer receives the whole picture without re-gathering four object types.

It computes NOTHING new and rolls nothing up: there is deliberately no ``.score()`` — that would BE
the forbidden scalar. A conflict on any axis is carried as-is (CHP-TRUST-008), never resolved into
false certainty. A product MAY derive a simplified label FROM a vector (CHP-TRUST-012), but the label
lives product-side and stays traceable back to this basis.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON


@dataclass(slots=True, frozen=True)
class AssuranceVector:
    """The assurance of a claim across its dimensions, none reduced to a scalar (CHP-TRUST-004).

    ``checks`` is the VerificationResult four-state per check (schema/integrity/issuer_identity/
    subject_binding/value_binding/freshness/revocation) verbatim. ``issuer_authority`` is the TRUST
    decision (separate from integrity, CHP-VER-011). ``corroboration`` is the count of INDEPENDENT
    sources (CHP-TRUST-006). ``effect`` is the EffectEvidence determination. ``conflicts`` preserves
    any unresolvable disagreement (CHP-TRUST-008)."""

    checks: JSON  # VerificationResult.checks, verbatim
    issuer_authority: str = "unknown"  # satisfied | unsatisfied | unknown
    corroboration: int = 0
    effect: str | None = None  # confirmed | indeterminate | unobserved | refuted
    conflicts: list[JSON] = field(default_factory=list)

    # The dimensions this vector preserves — named so a consumer/schema enumerates them (and so it is
    # provable that none is dropped). Not a scalar.
    DIMENSIONS: ClassVar[tuple[str, ...]] = (
        "integrity", "issuer_identity", "issuer_authority", "subject_binding", "value_binding",
        "freshness", "revocation", "corroboration", "effect",
    )

    def to_dict(self) -> JSON:
        data = asdict(self)
        if not self.conflicts:
            data.pop("conflicts", None)
        if self.effect is None:
            data.pop("effect", None)
        return data


def assurance_from(
    verification: object,
    *,
    issuer_authority: str = "unknown",
    corroboration: int = 0,
    effect: str | None = None,
    conflicts: list[JSON] | None = None,
) -> AssuranceVector:
    """Assemble the assurance vector from evidence that ALREADY exists (CHP-TRUST-004) — the
    VerificationResult's checks + the (separately decided) issuer authority + the independent
    corroboration count + the effect determination + any preserved conflicts. A projection, never a
    scalar rollup: it re-derives nothing, it only carries the dimensions together."""
    checks = dict(getattr(verification, "checks", None) or {})
    return AssuranceVector(checks=checks, issuer_authority=issuer_authority,
                           corroboration=corroboration, effect=effect,
                           conflicts=list(conflicts or []))
