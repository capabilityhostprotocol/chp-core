"""Verdict-free qualification (proposal 0050, Tier C; CHP-SUP-013).

A ``QualificationClaim`` records what has been OBSERVED about a capability's fitness FOR A PURPOSE —
as provenanced observations that CITE evidence (assertions, verification results, execution/effect
evidence) — and NEVER as a verdict. Qualification is contextual and derived by a consumer at
admission from the cited evidence; it is not a property of the capability. A claim that encodes a
conclusion (``qualified``/``authorized``/``approved``/``trusted``/``admitted``) anywhere is refused
(CHP-SUP-002 / CHP-SUP-013).

This mirrors the supply-side discipline (``supply.provenanced`` / CHP-SUP-012): an observation that
claims external verification or execution-derivation MUST cite the evidence that backs it — an
unbacked verification claim is exactly the masquerade the provenance rule exists to prevent.

Pure type (E2): the qualification PROCESS lives adapter-side; this is the record it produces.
chp-core carries the type + its invariants, never the implementation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

# Single source of truth for the supply-side grammar — do not duplicate these frozensets.
from .supply import PROVENANCE, _FORBIDDEN_CONCLUSIONS, _PROVENANCE_NEEDS_EVIDENCE
from .types import JSON, new_id, utc_now

# Re-export under public names for consumers of this module.
FORBIDDEN_CONCLUSIONS = _FORBIDDEN_CONCLUSIONS


def _validate_observation(o: object) -> None:
    """Enforce the observation grammar (CHP-SUP-012/013): a named, provenanced property that is not
    a conclusion, and that cites evidence when it claims verification or execution-derivation."""
    if not isinstance(o, dict):
        raise ValueError("each observation must be a dict")
    prop = o.get("property")
    if not isinstance(prop, str) or not prop:
        raise ValueError("observation.property must be a non-empty string")
    if prop in _FORBIDDEN_CONCLUSIONS:
        raise ValueError(f"observation property {prop!r} is a forbidden conclusion (CHP-SUP-013)")
    prov = o.get("provenance")
    if prov not in PROVENANCE:
        raise ValueError(f"observation.provenance must be one of {sorted(PROVENANCE)} (CHP-SUP-012)")
    if prov in _PROVENANCE_NEEDS_EVIDENCE and not o.get("evidence"):
        raise ValueError(f"{prov} observation MUST cite the evidence that backs it (CHP-SUP-012)")


def observation(property: str, value: object, provenance: str, *,
                evidence: list[str] | None = None) -> JSON:
    """Build one provenanced observation about the subject's fitness.

    ``externally_verified`` and ``execution_derived`` observations MUST cite ``evidence`` (assertion
    / verification-result / effect ids). ``self_asserted`` and ``inferred`` are honest about being
    unbacked and need none. The ``property`` names what was observed (e.g. ``"contract_conformance"``,
    ``"latency_p95_ms"``) — never a conclusion like ``qualified``.
    """
    obs: JSON = {"property": property, "value": value, "provenance": provenance}
    if evidence:
        obs["evidence"] = list(evidence)
    _validate_observation(obs)
    return obs


def _reject_conclusions(node: object) -> None:
    """Refuse any forbidden conclusion key set to a truthy value ANYWHERE in the claim — a claim is
    verdict-free by construction, not by convention (CHP-SUP-002 / CHP-SUP-013)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _FORBIDDEN_CONCLUSIONS and v:
                raise ValueError(
                    f"QualificationClaim must be verdict-free: {k!r} is a forbidden conclusion "
                    "(CHP-SUP-002/013)"
                )
            _reject_conclusions(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _reject_conclusions(v)


@dataclass
class QualificationClaim:
    """A verdict-free record of what has been observed about a capability's fitness for a purpose.

    - ``subject``: the capability (or binding) id under assessment.
    - ``purpose``: the use the fitness is assessed FOR — qualification is purpose-relative, never
      absolute (fit for one purpose is not fit for another).
    - ``assessor``: the entity id that made the observations (itself self-asserted unless an
      observation's provenance says otherwise).
    - ``observations``: provenanced, evidence-citing records of what was seen. They carry NO verdict;
      a consumer derives any qualification conclusion from the cited evidence at admission.

    The claim never concludes. ``__post_init__`` rejects any forbidden conclusion and validates every
    observation's provenance/evidence discipline.
    """

    subject: str
    purpose: str
    assessor: str
    observations: list[JSON] = field(default_factory=list)
    claim_id: str = field(default_factory=lambda: new_id("qc"))
    created_at: str = field(default_factory=utc_now)

    INVARIANT: ClassVar[str] = "CHP-SUP-013"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject:
            raise ValueError("QualificationClaim.subject is required")
        if not isinstance(self.purpose, str) or not self.purpose:
            raise ValueError(
                "QualificationClaim.purpose is required — qualification is purpose-relative "
                "(CHP-SUP-013)"
            )
        if not isinstance(self.assessor, str) or not self.assessor:
            raise ValueError("QualificationClaim.assessor is required")
        if not isinstance(self.observations, list):
            raise ValueError("QualificationClaim.observations must be a list")
        for o in self.observations:
            _validate_observation(o)
        _reject_conclusions(asdict(self))

    def cited_evidence(self) -> list[str]:
        """All evidence ids cited across the observations — what a consumer would check."""
        ids: list[str] = []
        for o in self.observations:
            ids.extend(o.get("evidence", []) or [])
        return ids

    def to_json(self) -> JSON:
        return asdict(self)
