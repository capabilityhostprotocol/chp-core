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

    def to_dict(self) -> JSON:
        data = asdict(self)
        for k in ("capability_declarations", "evidence_refs", "discovery_metadata", "service_metadata"):
            if not data.get(k):
                data.pop(k, None)
        return data


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
