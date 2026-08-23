"""Generalized evidence subject (CHP-CORE-019) — what a piece of evidence is ABOUT.

Evidence is not only about invocations. It can reference an entity, a capability, a binding, an
invocation, an execution, an artifact, an effect, or an extensible external subject — with NO
invocation subject required. EvidenceSubject is the one union other evidence records name as their
subject, so any of those can be the thing evidenced. ``kind`` is informational and grants nothing —
being the subject of evidence confers no capability, authority, or trust (mirrors CHP-ENT-003).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from .types import JSON

_KINDS = frozenset(
    {"entity", "capability", "binding", "invocation", "execution", "artifact", "effect", "external"}
)


@dataclass(slots=True, frozen=True)
class EvidenceSubject:
    """The subject a piece of evidence is about (CHP-CORE-019). kind ∈ the eight subject kinds;
    ``ref`` optionally locates an external/extensible subject (e.g. a scheme + uri). Frozen — a
    subject reference is a fact, not a mutable handle."""

    kind: str
    id: str
    ref: JSON = field(default_factory=dict)

    KINDS: ClassVar[frozenset[str]] = _KINDS

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"evidence subject kind must be one of {sorted(_KINDS)}")
        if not self.id:
            raise ValueError("evidence subject must name an id")

    def to_dict(self) -> JSON:
        d: JSON = {"kind": self.kind, "id": self.id}
        if self.ref:
            d["ref"] = self.ref
        return d
