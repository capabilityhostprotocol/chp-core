"""Resolver — CapabilityRequirement, CapabilityResolution, resolve() (proposal 0045, Tier C).

The resolver converts an abstract CapabilityRequirement into eligible, ranked candidates and,
when selected, an immutable CapabilityResolution. Its defining invariant is the HARD FILTER: no
amount of preference score may compensate for an unsatisfied mandatory requirement (CHP-RES-002)
— ranking happens ONLY after eligibility. Resolution is NOT admission (CHP-RES-008): selecting a
provider confers no execution authority; the resolved invocation still faces admission (0043).
The resolution record is immutable and deterministic, and preserves provenance (CHP-RES-007/009/016).
"""

from __future__ import annotations

from collections.abc import Callable
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
    required_evidence: list[str] = field(default_factory=list)  # evidence kinds needed (CHP-RES-005)
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
    evidence_contract: object | None = None  # candidate's EvidenceContract, for evidence fit (CHP-RES-005)
    source_market: JSON | None = None  # {id, ...} — the market/registry this candidate came from (CHP-FED-003)
    # The assertions/verification-results backing this candidate's claims, carried WITH it across a
    # market boundary so a RECEIVING market can re-verify locally rather than inherit the source's
    # verdict (CHP-FED-004). Optional — a self-market candidate needs none.
    evidence: list[JSON] | None = None
    # The exact offer {id, version} this candidate came from (CHP-SUP-006): preserved into the
    # resolution chain so a governance-relevant offer change (a bumped version) is pinned + auditable
    # and a mutable offer can't be swapped after selection. Optional — a non-offer candidate has none.
    offer: JSON | None = None


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
    # Pin the exact offer id+version into the candidate (CHP-SUP-006) so the resolution chain records
    # WHICH offer version was selected — a bumped-version offer is a distinct, auditable selection.
    oid = getattr(offer, "id", None) if not isinstance(offer, dict) else offer.get("id")
    over = getattr(offer, "version", None) if not isinstance(offer, dict) else offer.get("version")
    offer_ref = {"id": oid, "version": over} if oid is not None else None
    return ResolvedCandidate(binding=binding, satisfied_hard=list(satisfied_hard), score=score,
                             offer=offer_ref)


_HISTORY_RANK_CAP = 10


def soft_fit(requirement: CapabilityRequirement, candidate: ResolvedCandidate) -> int:
    """Score a candidate on the requirement's SOFT operational/commercial preferences — deadline,
    geography, availability, max_price, etc. (CHP-RES-006). A candidate's binding declares which soft
    constraints it ``meets``; the score is how many of the requested preferences it satisfies. This is
    a RANKING signal ONLY — it is added to a candidate's rank score, NEVER to eligibility, so a
    soft-superior candidate that fails a hard constraint is still excluded (CHP-RES-002)."""
    meets = set((candidate.binding or {}).get("meets") or [])
    return sum(1 for p in requirement.preferences if p in meets)


def history_rank(history: list[JSON] | None) -> int:
    """A capped RANKING signal from a candidate's capability-scoped execution/effect history
    (CHP-RES-014): more prior successes rank a candidate higher, bounded so history can never
    dominate. MUST NOT waive current mandatory evidence or admission invariants — this feeds the rank
    score only; the hard filter (and required-evidence fit) stay dominant and history never touches
    eligibility."""
    return min(sum(1 for h in (history or []) if h.get("outcome") == "success"), _HISTORY_RANK_CAP)


def resolve(
    requirement: CapabilityRequirement,
    candidates: list[ResolvedCandidate],
    *,
    provenance: JSON | None = None,
    require_fit: CapabilityDefinition | None = None,
    rank_bonus: Callable[[ResolvedCandidate], int] | None = None,
) -> CapabilityResolution:
    """Filter candidates to the ELIGIBLE (those satisfying EVERY hard constraint — CHP-RES-002,
    no score compensates), rank the eligible by score descending, and select the top. The
    ranking is deterministic (score, then binding id tiebreak — CHP-RES-016). An empty eligible
    set yields an unresolved resolution, never a silent pick.

    When ``require_fit`` (the requirement's CapabilityDefinition) is given, functional fit is
    COMPUTED per candidate (CHP-RES-003). When ``requirement.required_evidence`` is non-empty,
    evidence fit is COMPUTED against each candidate's EvidenceContract (CHP-RES-005). A candidate
    is eligible only when EVERY computed fit is 'satisfied'; 'unknown'/'unsatisfied' EXCLUDES it —
    unknown is never silently promoted (CHP-RES-011). Each computed fit is recorded per candidate."""
    from .contract import SATISFIED, UNKNOWN, evidence_fit, functional_fit

    required = set(requirement.hard)
    need_evidence = bool(requirement.required_evidence)

    def fits_of(c: ResolvedCandidate) -> dict[str, str]:
        fits: dict[str, str] = {}
        if require_fit is not None:
            fits["functional_fit"] = (
                functional_fit(require_fit, c.definition) if c.definition is not None else UNKNOWN)
        if need_evidence:
            fits["evidence_fit"] = evidence_fit(requirement.required_evidence, c.evidence_contract)
        return fits

    scored = [(c, fits_of(c)) for c in candidates]
    eligible = [
        (c, fits) for c, fits in scored
        if required <= set(c.satisfied_hard) and all(v == SATISFIED for v in fits.values())
    ]
    # Ranking (CHP-RES-006/014): among the ELIGIBLE only, add any soft operational/commercial or
    # history signal to the score. rank_bonus is applied AFTER the hard filter, so it can reorder
    # eligible candidates but can never make an ineligible one selectable.
    def _rank_score(c: ResolvedCandidate) -> int:
        return c.score + (rank_bonus(c) if rank_bonus is not None else 0)

    ranked = sorted(eligible, key=lambda cf: (-_rank_score(cf[0]), str(cf[0].binding.get("id", ""))))
    selected = ranked[0][0].binding if ranked else None

    def record(c: ResolvedCandidate, fits: dict[str, str]) -> JSON:
        rec: JSON = {"binding": c.binding, "score": c.score, "satisfied_hard": sorted(c.satisfied_hard)}
        rec.update(fits)
        if c.source_market is not None:  # preserve federated source provenance (CHP-FED-003)
            rec["source_market"] = c.source_market
        if c.offer is not None:  # pin the exact offer version selected (CHP-SUP-006)
            rec["offer"] = c.offer
        return rec

    return CapabilityResolution(
        requirement_id=requirement.id,
        selected=selected,
        candidates=[record(c, fits) for c, fits in ranked],
        provenance=provenance or {},
        result="resolved" if selected is not None else "unresolved",
    )
