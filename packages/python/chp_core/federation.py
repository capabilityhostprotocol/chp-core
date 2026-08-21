"""Market federation policy — MarketDescriptor, federable(), source-priority ordering.

Federating the capability market REUSES the deep evidence/trust primitives — verify_task_bundle +
per-verifier ``trusted_issuers`` for LOCAL reverification (a receiving market never trusts a remote
verdict, FED-004; there is no global identity authority, FED-005) — and adds only the thin POLICY
layer on top:

- A ``MarketDescriptor`` is the contract a federating market exposes (FED-002): which source markets
  it prefers, which capabilities are too sensitive to federate, and its own trusted issuers.
- ``federable()`` decides, PER REQUIREMENT, whether it may be federated at all (FED-001) — a
  sensitive capability is PROHIBITED from leaving a private market (FED-007).
- ``source_priority_key()`` orders candidates by their source market (internal-first, then approved
  partners, then public — FED-009). It is a RANKING input only: it never overrides a hard constraint
  (that stays the resolver's job) and never confers trust (that stays local reverification).

Source-market provenance itself rides on ``ResolvedCandidate.source_market`` (FED-003) — the resolver
preserves it into the resolution so a receiving market always knows where a candidate came from.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .types import JSON, new_id


@dataclass(slots=True)
class MarketDescriptor:
    """The federation contract a market exposes (FED-002) — e.g. at /.well-known/chp-market. It
    declares policy, never trust conclusions: ``trusted_issuers`` is THIS market's local trust set
    for its own reverification, not a claim other markets must honor."""

    market_id: str
    federates: bool = False                                       # whether this market federates at all
    source_priority: list[str] = field(default_factory=list)      # ordered source market ids, most-preferred first
    sensitive_capabilities: list[str] = field(default_factory=list)  # capability ids that MUST NOT federate
    trusted_issuers: list[str] = field(default_factory=list)      # this market's LOCAL trust set (FED-004)
    id: str = field(default_factory=lambda: new_id("mkt"))

    def to_dict(self) -> JSON:
        return asdict(self)


def federable(requirement: object, descriptor: MarketDescriptor) -> bool:
    """Whether a CapabilityRequirement may be federated out of this market (FED-001/007). False when
    the market does not federate at all, or the requirement's capability is marked sensitive — a
    sensitive capability is PROHIBITED from federating regardless of anything else (FED-007)."""
    if not descriptor.federates:
        return False
    cap = getattr(requirement, "capability", None)
    cap_id = cap.get("id") if isinstance(cap, dict) else None
    return cap_id not in set(descriptor.sensitive_capabilities)


def source_priority_key(candidate: object, descriptor: MarketDescriptor) -> int:
    """An ordering key for a candidate by its source market per the descriptor's ``source_priority``
    (FED-009): lower = more preferred; a candidate from an unlisted/unknown source sorts LAST. A
    ranking input only — it never overrides a hard constraint and never confers trust."""
    src_market = getattr(candidate, "source_market", None)
    src = src_market.get("id") if isinstance(src_market, dict) else None
    order = descriptor.source_priority
    return order.index(src) if src in order else len(order)
