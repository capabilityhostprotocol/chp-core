"""Resolver — CapabilityRequirement, CapabilityResolution, resolve() (proposal 0045, Tier C).

The resolver converts an abstract CapabilityRequirement into eligible, ranked candidates and,
when selected, an immutable CapabilityResolution. Its defining invariant is the HARD FILTER: no
amount of preference score may compensate for an unsatisfied mandatory requirement (CHP-RES-002)
— ranking happens ONLY after eligibility. Resolution is NOT admission (CHP-RES-008): selecting a
provider confers no execution authority; the resolved invocation still faces admission (0043).
The resolution record is immutable and deterministic, and preserves provenance (CHP-RES-007/009/016).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

from .types import JSON, new_id, utc_now

if TYPE_CHECKING:
    from .capability_definition import CapabilityDefinition


@dataclass(slots=True)
class CapabilityRequirement:
    """What a requester needs: an abstract capability + mandatory (hard) constraints +
    preferences (proposal 0045; CHP-RES-001). Hard constraints are eligibility gates;
    preferences only rank among the eligible. A requirement is NOT an invocation (CHP-SUP-001)."""

    capability: JSON  # {id, version?}
    hard: list[str] = field(default_factory=list)  # names of mandatory constraints
    preferences: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("req"))

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class ResolvedCandidate:
    """A candidate binding scored against a requirement — descriptive, not authoritative.
    satisfied_hard lists which mandatory constraints this candidate satisfies; score (an int
    ranking signal, never CHP truth) ranks ONLY among the eligible. ``definition`` is the
    candidate's CapabilityDefinition, supplied when the resolver should COMPUTE functional fit
    (resolve(require_fit=...)) rather than trust asserted satisfied_hard (CHP-RES-003)."""

    binding: JSON  # {id, ...}
    satisfied_hard: list[str] = field(default_factory=list)
    score: int = 0
    definition: CapabilityDefinition | None = None  # supplied when computed fit is used


@dataclass(slots=True)
class CapabilityResolution:
    """The immutable record of resolving a requirement to a selected candidate (proposal 0045;
    CHP-RES-007/009/016). Records the ranked eligible candidates, the selection, and provenance
    (the policy/relationship/assertion inputs that allowed it). NOT admission (CHP-RES-008)."""

    requirement_id: str
    selected: JSON | None  # the chosen candidate's binding, or None if unresolved
    candidates: list[JSON]  # ranked eligible candidates: [{binding, score, satisfied_hard}]
    provenance: JSON  # {policy, relationships?, assertions?}
    result: str  # resolved | unresolved
    id: str = field(default_factory=lambda: new_id("cres"))
    resolved_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.selected is None:
            data.pop("selected", None)
        return data


def offer_to_candidate(offer: object, *, satisfied_hard: list[str], score: int = 0) -> ResolvedCandidate:
    """Build a resolver candidate from a published CapabilityOffer — the supply→resolve seam
    (proposal 0049). ``offer`` is a CapabilityOffer (or a dict with a ``binding``). The candidate
    is DESCRIPTIVE: which hard constraints the offer supports is the CALLER's evaluation (against
    the offer's EvidenceContract + verified assertions), NEVER a conclusion baked into the offer
    (CHP-SUP-002/007). No score compensates for a missing hard constraint at resolve() time."""
    binding = offer.binding if hasattr(offer, "binding") else offer["binding"]  # type: ignore[index]
    return ResolvedCandidate(binding=binding, satisfied_hard=list(satisfied_hard), score=score)


def resolve(
    requirement: CapabilityRequirement,
    candidates: list[ResolvedCandidate],
    *,
    provenance: JSON | None = None,
    require_fit: CapabilityDefinition | None = None,
) -> CapabilityResolution:
    """Filter candidates to the ELIGIBLE (those satisfying EVERY hard constraint — CHP-RES-002,
    no score compensates), rank the eligible by score descending, and select the top. The
    ranking is deterministic (score, then binding id tiebreak — CHP-RES-016). An empty eligible
    set yields an unresolved resolution, never a silent pick.

    When ``require_fit`` (the requirement's CapabilityDefinition) is given, functional fit is
    COMPUTED per candidate (CHP-RES-003): a candidate is eligible only when its fit is
    'satisfied'. Fit that is 'unknown' or 'unsatisfied' EXCLUDES the candidate — unknown is never
    silently promoted (CHP-RES-011). The computed fit is recorded on each candidate record."""
    from .contract import SATISFIED, UNKNOWN, functional_fit

    required = set(requirement.hard)

    def fit_of(c: ResolvedCandidate) -> str | None:
        if require_fit is None:
            return None
        return functional_fit(require_fit, c.definition) if c.definition is not None else UNKNOWN

    scored = [(c, fit_of(c)) for c in candidates]
    eligible = [
        (c, f) for c, f in scored
        if required <= set(c.satisfied_hard) and (f is None or f == SATISFIED)
    ]
    ranked = sorted(eligible, key=lambda cf: (-cf[0].score, str(cf[0].binding.get("id", ""))))
    selected = ranked[0][0].binding if ranked else None

    def record(c: ResolvedCandidate, f: str | None) -> JSON:
        rec: JSON = {"binding": c.binding, "score": c.score, "satisfied_hard": sorted(c.satisfied_hard)}
        if f is not None:
            rec["functional_fit"] = f
        return rec

    return CapabilityResolution(
        requirement_id=requirement.id,
        selected=selected,
        candidates=[record(c, f) for c, f in ranked],
        provenance=provenance or {},
        result="resolved" if selected is not None else "unresolved",
    )
