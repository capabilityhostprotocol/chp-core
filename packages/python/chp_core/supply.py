"""Supply types — ProviderProfile, CapabilityOffer, EvidenceContract (proposal 0048, Tier C).

The descriptive supply-side records the resolver's candidates are built from. Supply is
downstream of the entity registry: a Provider is a role an Entity plays, and a ProviderProfile
is a supply projection over that entity — descriptive, never a permanent conclusion. A
CapabilityOffer packages a binding into something selectable; publishing one is NOT admission
(CHP-SUP-008). An EvidenceContract declares what evidence execution is EXPECTED to produce — a
PROMISE, not evidence (EvidenceContract ≠ Evidence, CHP-CAP-014); CHP Core evaluates the actual
evidence at execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, new_id

# Permanent conclusions a descriptive supply record must never encode (CHP-SUP-002): these are
# contextual and derived at admission, not properties of a provider.
_FORBIDDEN_CONCLUSIONS = frozenset({"qualified", "authorized", "approved", "trusted", "admitted"})

# Provenance of a supply-record property (CHP-SUP-012): a supply record MUST preserve HOW each
# provider/capability property came to be known, so a self-assertion can never be read as verified.
PROVENANCE = frozenset({"self_asserted", "externally_verified", "inferred", "execution_derived"})
# The two provenances that make a truth claim about the world MUST cite the evidence backing them —
# claiming external verification or execution-derivation without evidence is exactly the masquerade
# provenance exists to prevent. self_asserted (the provider's own word) and inferred (a discovery
# signal, CHP-SUP-004) are honest about being unbacked and need no evidence.
_PROVENANCE_NEEDS_EVIDENCE = frozenset({"externally_verified", "execution_derived"})


def provenanced(value: object, provenance: str, *, evidence: list[str] | None = None) -> JSON:
    """Tag a provider/capability property VALUE with its provenance (CHP-SUP-012): whether it is
    self-asserted, externally verified, inferred, or execution-derived. ``externally_verified`` and
    ``execution_derived`` MUST cite the evidence (assertion / verification-result / effect ids) that
    backs them — an unbacked verification claim is refused."""
    if provenance not in PROVENANCE:
        raise ValueError(f"provenance must be one of {sorted(PROVENANCE)}")
    if provenance in _PROVENANCE_NEEDS_EVIDENCE and not evidence:
        raise ValueError(f"{provenance} property MUST cite the evidence that backs it (CHP-SUP-012)")
    tag: JSON = {"value": value, "provenance": provenance}
    if evidence:
        tag["evidence"] = list(evidence)
    return tag


def provenance_of(tag: object) -> str | None:
    """The provenance kind of a tagged property, or None if the value carries no provenance tag."""
    return tag.get("provenance") if isinstance(tag, dict) else None


def validate_provenance(tag: JSON) -> None:
    """Raise if a provenance-tagged property is malformed (unknown kind, or a verified/derived claim
    with no evidence). A value that is not a provenance tag is left alone — provenance is opt-in per
    property, but any tag that IS present must be well-formed."""
    prov = tag.get("provenance")
    if prov is None:
        return
    provenanced(tag.get("value"), prov, evidence=tag.get("evidence"))


@dataclass(slots=True)
class EvidenceContract:
    """Declares what evidence an execution is EXPECTED to produce (proposal 0048; CHP-CAP-014,
    CHP-SUP-007). A PROMISE, not evidence — EvidenceContract ≠ Evidence. It MUST NOT assert the
    evidence already exists; CHP Core evaluates the actual evidence at execution time."""

    id: str
    execution_produces: list[str]  # the evidence kinds execution is expected to yield
    effect_observation: JSON = field(default_factory=lambda: {"available": False})

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class ProviderProfile:
    """A DESCRIPTIVE supply projection over an entity + capability declarations + evidence refs
    (proposal 0048; CHP-SUP-002). MUST NOT encode context-free permanent conclusions
    (qualified/authorized/approved/... = true) — __post_init__ rejects them."""

    entity: JSON  # the durable entity ref this provider role belongs to
    id: str = field(default_factory=lambda: new_id("prov"))
    capability_declarations: list[JSON] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    discovery_metadata: JSON = field(default_factory=dict)
    service_metadata: JSON = field(default_factory=dict)

    FORBIDDEN_CONCLUSIONS: ClassVar[frozenset[str]] = _FORBIDDEN_CONCLUSIONS

    def __post_init__(self) -> None:
        for meta in (self.discovery_metadata, self.service_metadata):
            bad = _FORBIDDEN_CONCLUSIONS & {k for k, v in meta.items() if v is True}
            if bad:
                raise ValueError(
                    f"ProviderProfile must not encode permanent conclusions: {sorted(bad)}"
                )
        # CHP-SUP-012: any property carrying a provenance tag must be well-formed, so a
        # self-assertion can't be dressed up as externally verified without citing evidence.
        tagged = [v for meta in (self.discovery_metadata, self.service_metadata) for v in meta.values()]
        tagged += [v for d in self.capability_declarations if isinstance(d, dict) for v in d.values()]
        for v in tagged:
            if isinstance(v, dict):
                validate_provenance(v)

    def to_dict(self) -> JSON:
        data = asdict(self)
        for k in ("capability_declarations", "evidence_refs", "discovery_metadata", "service_metadata"):
            if not data.get(k):
                data.pop(k, None)
        return data


def offer_validity_state(offer: object, at: str | None = None) -> str:
    """The validity state of an offer at time *at* (ISO-8601 Z; default now):
    ``current`` | ``expired`` | ``not_yet_valid`` | ``unbounded``.

    Reads the offer's ``validity`` {valid_from?, valid_until?}. An offer with no
    validity bounds is ``unbounded`` — honest about carrying no lease claim.
    Lexicographic comparison is exact for ISO-8601 UTC timestamps."""
    from .types import utc_now
    if hasattr(offer, "validity"):
        validity = offer.validity or {}
    elif isinstance(offer, dict):
        validity = offer.get("validity") or {}
    else:
        validity = {}
    if not validity.get("valid_from") and not validity.get("valid_until"):
        return "unbounded"
    now = at or utc_now()
    if validity.get("valid_from") and now < validity["valid_from"]:
        return "not_yet_valid"
    if validity.get("valid_until") and now >= validity["valid_until"]:
        return "expired"
    return "current"


def current_offers(offers: list, at: str | None = None) -> list:
    """Filter offers to those resolvable NOW: expired or not-yet-valid supply
    MUST NOT be resolved as current supply — staleness is an eligibility fact,
    never a ranking signal."""
    return [o for o in offers if offer_validity_state(o, at) in ("current", "unbounded")]


@dataclass(slots=True)
class CapabilityOffer:
    """Packages a CapabilityBinding into a selectable offer (proposal 0048; CHP-SUP-005). Offers
    are NOT Core execution records; publishing one is NOT admission (CHP-SUP-008). A
    governance-relevant change produces a new offer version (CHP-SUP-006)."""

    binding: JSON  # the CapabilityBinding (or its ref)
    provider: JSON  # provider ref
    evidence_contract: JSON  # an EvidenceContract (or its ref) — expected evidence, a promise
    id: str = field(default_factory=lambda: new_id("offer"))
    version: str = "1"
    service_scope: JSON = field(default_factory=dict)
    jurisdiction: str | None = None
    availability: JSON = field(default_factory=dict)
    commercial_terms: JSON = field(default_factory=dict)
    validity: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.jurisdiction is None:
            data.pop("jurisdiction", None)
        for k in ("service_scope", "availability", "commercial_terms", "validity"):
            if not data.get(k):
                data.pop(k, None)
        return data
