"""Running-instance identity — the live instance an activation produces.

A **RunningInstance** is the identity of a live capability instance made
operational by an activation: provisioned (DEPLOY), run in a CHP-native runtime
(INSTANTIATE), or bound to an existing service (CONNECT). It is DISTINCT from the
semantic capability, the software/artifact, the offering, and the binding
(CHP-CORE-021) — those name *what* and *where*; the running instance is the *live
thing* that exists after activation.

Identity is a STABLE id that survives health/status transitions (the CHP-ENT-003
ethic: identity is stable across state the world observes). ``status`` is mutable
state recorded ABOUT the instance, never part of its identity; a transition
constructs a NEW record with the SAME id (history is immutable — a relying store
appends, never mutates). A terminated instance keeps its id.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import ClassVar

from .types import JSON, new_id, utc_now


@dataclass(slots=True, frozen=True)
class RunningInstance:
    """Identity + current recorded state of a live, activated capability instance.

    FROZEN: a record is immutable; ``with_status`` returns a NEW record preserving
    the id (and activated_at), so identity is stable across status changes."""

    capability_id: str       # the semantic capability this instance serves
    host_id: str             # the destination host where it runs / is bound
    binding_digest: str      # content address of the CapabilityBinding it realizes
    strategy: str            # the activation strategy that produced it
    artifact: JSON = field(default_factory=dict)  # {ref|digest} of the software/artifact that runs
    status: str = "provisioning"
    id: str = field(default_factory=lambda: new_id("inst"))
    plan_digest: str | None = None  # the activation plan that produced this instance
    activated_at: str = field(default_factory=utc_now)

    STATUSES: ClassVar[frozenset[str]] = frozenset(
        {"provisioning", "running", "degraded", "terminated"}
    )
    STRATEGIES: ClassVar[frozenset[str]] = frozenset({"CONNECT", "DEPLOY", "INSTANTIATE"})

    def __post_init__(self) -> None:
        if self.strategy not in self.STRATEGIES:
            raise ValueError(f"strategy must be one of {sorted(self.STRATEGIES)}")
        if self.status not in self.STATUSES:
            raise ValueError(f"status must be one of {sorted(self.STATUSES)}")
        for name in ("capability_id", "host_id", "binding_digest"):
            if not getattr(self, name):
                raise ValueError(f"running instance missing {name!r}")

    def with_status(self, status: str) -> "RunningInstance":
        """A new record at a new status, SAME identity (id + activated_at preserved).
        Models stable-identity-across-state: a store appends this, never mutates."""
        if status not in self.STATUSES:
            raise ValueError(f"status must be one of {sorted(self.STATUSES)}")
        return replace(self, status=status)

    def is_operational(self) -> bool:
        return self.status == "running"

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.plan_digest is None:
            data.pop("plan_digest", None)
        return data
