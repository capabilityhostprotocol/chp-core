"""Entity identity kernel — EntitySubject (proposal 0044, Tier B).

A durable entity is the stable SUBJECT of assertions, capabilities, and roles. Its id is
STABLE across mutable display / external-identifier / key / endpoint changes; only an explicit
succession event creates a NEW entity (CHP-ENT-001). It is distinct from the CONTEXTUAL ROLES
(Actor, Principal, Provider, Host, Executor, Issuer, Verifier) a durable entity plays
(CHP-ARCH-003) — EntitySubject is not a rename of Actor.

kind is informational and MUST NOT itself grant capability, qualification, trust, authority,
or admission (CHP-ENT-003). External identifiers (email/domain/cert) are CLAIMS, not canonical
identity (CHP-ENT-002) — each carries the Assertion that backs the binding. Lifecycle status
is orthogonal; offboarding preserves history and never rewrites it (CHP-ENT-006/012).

This is the identity KERNEL; the onboarding/market record (registry/management/publication)
layers on top later.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, utc_now

_STATUSES = frozenset({"active", "suspended", "offboarded"})


@dataclass(slots=True)
class EntitySubject:
    """A durable entity with a stable id. See module docstring for the invariants."""

    id: str
    kind: str
    status: str = "active"
    display: JSON = field(default_factory=dict)  # mutable, non-identifying
    # External identifiers as evidence-backed CLAIMS (CHP-ENT-002), NOT canonical identity —
    # each entry references the Assertion that binds it: {"kind","value","assertion"}.
    identifiers: list[JSON] = field(default_factory=list)
    assertion_refs: list[str] = field(default_factory=list)
    # Explicit succession (CHP-ENT-001): a new entity that continues a predecessor names it
    # here. Absent for an original entity; rotation/profile changes NEVER set this.
    succeeds_id: str | None = None
    version: str = "1"
    created_at: str = field(default_factory=utc_now)

    STATUSES: ClassVar[frozenset[str]] = _STATUSES

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError(f"entity status must be one of {sorted(_STATUSES)}")

    def ref(self) -> JSON:
        """The EntityRef for use as an Assertion/binding subject: {kind, id}. Carries only the
        stable identity + informational kind — never authority or trust."""
        return {"kind": self.kind, "id": self.id}

    def succeed(self, new_id: str, **overrides: object) -> "EntitySubject":
        """Create the SUCCESSOR entity (a new durable entity, new id) that continues self —
        the ONLY way identity changes (CHP-ENT-001). History of self is preserved; the
        successor links back via succeeds_id. Optional overrides seed the successor's fields."""
        base: dict = {"kind": self.kind, "display": dict(self.display)}
        base.update(overrides)
        return EntitySubject(id=new_id, succeeds_id=self.id, **base)  # type: ignore[arg-type]

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.succeeds_id is None:
            data.pop("succeeds_id", None)
        for k in ("display",):
            if not data.get(k):
                data.pop(k, None)
        for k in ("identifiers", "assertion_refs"):
            if not data.get(k):
                data.pop(k, None)
        return data
