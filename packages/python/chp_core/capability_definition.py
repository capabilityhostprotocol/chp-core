"""Capability definition + relationship algebra (proposal 0045, Tier C).

A CapabilityDefinition is a SEMANTIC capability independent of any one provider/host/transport/
price/availability (CHP-CAP-001) — the thing a resolver matches a requirement against. It is
distinct from CapabilityDescriptor (the live, provider/executor-coupled runtime descriptor).

The relationship algebra governs when one capability may substitute for another. Its whole
point is restraint: a declared relationship ALONE never grants substitution — an explicit
resolver policy must accept it, and semantic similarity is NEVER equivalence (CHP-CAP-009/015).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON

_REL_TYPES = frozenset(
    {"supersedes", "compatible_with", "subtype_of", "equivalent_to", "implements"}
)
_EFFECT_CLASSES = frozenset({
    "advisory", "observational", "attestational", "transactional",
    "transformative", "physical", "representational", "authoritative",
})


class CapabilityRelationship:
    """The substitution/transitivity rules of the algebra (08_capability_relationship_algebra).
    Pure policy logic over DECLARED relationships — never over similarity."""

    @staticmethod
    def may_substitute(
        relationship_type: str,
        *,
        policy_accepts_authority: bool = False,
        direction: str = "forward",
        migration_policy: bool = False,
    ) -> bool:
        """Whether a declared relationship ALONE permits substituting one capability for
        another. Default-deny: every path requires an explicit policy input (CHP-CAP-015..019).
        - equivalent_to: only when resolver policy accepts the asserting authority.
        - subtype_of: direction-sensitive (a narrowing subtype) AND policy-controlled.
        - supersedes: NO automatic migration — requires an explicit migration policy.
        - compatible_with / implements / anything else: never auto-substitutable."""
        if relationship_type == "equivalent_to":
            return policy_accepts_authority
        if relationship_type == "subtype_of":
            return direction == "narrowing" and policy_accepts_authority
        if relationship_type == "supersedes":
            return migration_policy
        return False  # compatible_with, implements, similarity, unknown → never

    @staticmethod
    def is_transitive(relationship_type: str) -> bool:
        """compatible_with is NOT transitive (CHP-CAP-017); equivalent_to (within one basis),
        subtype_of (while constraints hold), and supersedes (version lineage) chain."""
        return relationship_type in {"equivalent_to", "subtype_of", "supersedes"}

    @staticmethod
    def is_symmetric(relationship_type: str) -> bool:
        return relationship_type == "equivalent_to"


@dataclass(slots=True)
class CapabilityDefinition:
    """A provider-independent semantic capability. See module docstring."""

    id: str
    version: str
    namespace: JSON  # {"authority": {"id": ...}} — the namespace authority (CHP-CAP-002)
    description: str
    input_schema: JSON | None = None
    output_schema: JSON | None = None
    effect: JSON | None = None  # {"class": one of _EFFECT_CLASSES}
    relationships: list[JSON] = field(default_factory=list)  # [{type, target{id,version?}}]

    REL_TYPES: ClassVar[frozenset[str]] = _REL_TYPES
    EFFECT_CLASSES: ClassVar[frozenset[str]] = _EFFECT_CLASSES

    def __post_init__(self) -> None:
        for rel in self.relationships:
            if rel.get("type") not in _REL_TYPES:
                raise ValueError(f"relationship type must be one of {sorted(_REL_TYPES)}")
            if not isinstance(rel.get("target"), dict) or not rel["target"].get("id"):
                raise ValueError("relationship target must be an object with an id")
        if self.effect is not None:
            cls = self.effect.get("class")
            if cls is not None and cls not in _EFFECT_CLASSES:
                raise ValueError(f"effect class must be one of {sorted(_EFFECT_CLASSES)}")

    def to_dict(self) -> JSON:
        data = asdict(self)
        for k in ("input_schema", "output_schema", "effect"):
            if data.get(k) is None:
                data.pop(k, None)
        if not data.get("relationships"):
            data.pop("relationships", None)
        return data
