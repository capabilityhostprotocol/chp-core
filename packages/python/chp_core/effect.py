"""Effect evidence — EffectEvidence (proposal 0047, CHP-CORE-016).

An observation of an external side effect, represented as evidence DISTINCT from executor
completion status. The executor reporting 'completed' is not the same as the effect being
observed: a command can complete while its physical/external effect is unknown, and an effect
can be confirmed, refuted, or never observed independently of how the execution reported.

EffectEvidence therefore carries its own OBSERVER provenance (who observed it — not the
executor's self-report) and a four-state determination
(confirmed / indeterminate / unobserved / refuted). indeterminate ties to CHP-CORE-014 — a
side effect that cannot be safely known — and is NEVER silently read as confirmed. Records are
append-only: a later reconciliation ADDS an EffectEvidence and never rewrites an earlier one
(CHP-CORE-015).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, new_id, utc_now


@dataclass(slots=True)
class EffectEvidence:
    """An observed external effect of an invocation. See module docstring for the invariants."""

    invocation_id: str
    subject: JSON  # the effect subject, e.g. {"kind": "effect", "id": ...}
    determination: str  # confirmed | indeterminate | unobserved | refuted
    observer: JSON  # {"id": ...} — who observed the effect (provenance, NOT the executor)
    id: str = field(default_factory=lambda: new_id("eff"))
    execution_id: str | None = None  # the execution attempt this effect relates to
    observed_state: JSON = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    observed_at: str = field(default_factory=utc_now)

    CONFIRMED: ClassVar[str] = "confirmed"
    INDETERMINATE: ClassVar[str] = "indeterminate"
    UNOBSERVED: ClassVar[str] = "unobserved"
    REFUTED: ClassVar[str] = "refuted"
    DETERMINATIONS: ClassVar[frozenset[str]] = frozenset(
        {"confirmed", "indeterminate", "unobserved", "refuted"}
    )

    def __post_init__(self) -> None:
        if self.determination not in self.DETERMINATIONS:
            raise ValueError(
                f"effect determination must be one of {sorted(self.DETERMINATIONS)}"
            )
        if not (isinstance(self.subject, dict) and self.subject.get("id")):
            raise ValueError("effect subject must be an object with an id")

    def is_confirmed(self) -> bool:
        """The effect was observed to have occurred. NOT execution success — a completed
        execution may have an indeterminate/refuted/unobserved effect (CHP-CORE-016). Only
        'confirmed' confirms; indeterminate/unobserved/refuted never do (CHP-CORE-014)."""
        return self.determination == self.CONFIRMED

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.execution_id is None:
            data.pop("execution_id", None)
        for k in ("observed_state", "evidence_refs"):
            if not data.get(k):
                data.pop(k, None)
        return data
