"""Commerce records — Quote / Order / Payment + dispute bundles + scoped metrics (market wave).

The market layer of the Capability Economy. A buyer accepts a priced ``Quote`` for a resolved
``CapabilityOffer``, places an ``Order`` bound to the governed resolution, and settles ``Payment``
on an EXTERNAL rail. These are SHARED market semantics — every public/private CHP market reuses them
(MKT-013), so they live once, here, and are never forked into a product (CHP-ENG-011).

Two disciplines the requirements demand:

- **Commerce ≠ Invocation (MKT-015).** A commerce record REFERENCES the governed records
  (requirement / resolution / offer / invocation) by id but never embeds execution truth — it has no
  outcome, no evidence, no content-hash. Its id namespace (``quo_`` / ``ord_`` / ``pay_`` / ``dsp_``)
  keeps it distinguishable from an invocation/evidence record.
- **Payment is NOT a CHP primitive (MKT-014).** ``Payment`` links an external rail's own settlement
  reference to an ``Order``; chp_core processes no payment and stays dependency-free.

Reputation is a PROJECTION, never a stored score (MKT-010/011): ``scoped_metrics`` derives
per-capability effect counts from EffectEvidence at read time — there is no universal reputation
number, and indeterminate is surfaced, never folded into confirmed.

Money is carried as a decimal STRING, never a float (no binary-rounding on a money path). Apache-2.0.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, new_id, utc_now

# Fields that would smuggle execution truth into a commerce record (MKT-015) — a commerce record
# must reference the governed records, never embed one. Exposed so a market (or a test) can assert
# no commerce record carries them.
INVOCATION_FIELDS: frozenset[str] = frozenset(
    {"outcome", "evidence", "content_hash", "prev_hash", "payload_commitment"}
)


@dataclass(slots=True)
class Quote:
    """A priced response to a requirement for a resolved offer (MKT-015). A quote is COMMERCIAL, not
    a grant to execute — publishing/accepting it is never admission."""

    offer_ref: str          # the CapabilityOffer id
    requirement_ref: str    # the CapabilityRequirement id
    amount: str             # decimal string — never a float on a money path
    currency: str
    id: str = field(default_factory=lambda: new_id("quo"))
    valid_until: str | None = None
    issued_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.valid_until is None:
            data.pop("valid_until", None)
        return data


@dataclass(slots=True)
class Order:
    """A buyer's commitment to a Quote, bound to the governed resolution (MKT-015). References the
    quote + resolution by id; DISTINCT from the Invocation its fulfilment will later produce."""

    quote_ref: str
    resolution_ref: str     # the CapabilityResolution id (the governed selection)
    buyer: JSON             # {id}
    id: str = field(default_factory=lambda: new_id("ord"))
    status: str = "placed"  # placed | fulfilled | cancelled | disputed
    invocation_ref: str | None = None  # the fulfilling invocation id — a REFERENCE, never the record
    placed_at: str = field(default_factory=utc_now)

    STATUSES: ClassVar[frozenset[str]] = frozenset({"placed", "fulfilled", "cancelled", "disputed"})

    def __post_init__(self) -> None:
        if self.status not in self.STATUSES:
            raise ValueError(f"order status must be one of {sorted(self.STATUSES)}")

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.invocation_ref is None:
            data.pop("invocation_ref", None)
        return data


@dataclass(slots=True)
class Payment:
    """Settlement of an Order on an EXTERNAL payment rail (MKT-014). chp_core does NOT process
    payment — this record links the rail's own transaction reference to the Order. ``rail`` is the
    external processor id (e.g. 'stripe', 'invoice', 'wire'); ``external_ref`` is opaque to CHP."""

    order_ref: str
    rail: str
    external_ref: str
    amount: str
    currency: str
    id: str = field(default_factory=lambda: new_id("pay"))
    status: str = "pending"  # pending | settled | refunded | failed
    settled_at: str | None = None

    STATUSES: ClassVar[frozenset[str]] = frozenset({"pending", "settled", "refunded", "failed"})

    def __post_init__(self) -> None:
        if self.status not in self.STATUSES:
            raise ValueError(f"payment status must be one of {sorted(self.STATUSES)}")

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.settled_at is None:
            data.pop("settled_at", None)
        return data


def dispute_bundle(order: Order, *, requirement_ref: str, resolution_ref: str, offer_ref: str,
                   evidence_refs: list[str], reason: str = "") -> JSON:
    """Assemble a reconstructable dispute bundle (MKT-016) from the commerce + governed records a
    dispute is adjudicated over — the order plus the requirement/resolution/offer it derives from and
    the execution/effect evidence refs. It PROJECTS references; it never rewrites a governed record."""
    return {
        "kind": "dispute-bundle",
        "id": new_id("dsp"),
        "order_ref": order.id,
        "requirement_ref": requirement_ref,
        "resolution_ref": resolution_ref,
        "offer_ref": offer_ref,
        "evidence_refs": list(evidence_refs),
        "reason": reason,
        "opened_at": utc_now(),
    }


def scoped_metrics(effects: list, *, capability: str) -> JSON:
    """Project per-capability effect metrics from EffectEvidence (MKT-010) — scoped to ONE
    capability, computed at read time, NEVER a stored or universal score (MKT-011). ``effects`` are
    the EffectEvidence records observed for this capability. indeterminate is surfaced in its own
    bucket and is NEVER folded into confirmed (CHP-CORE-014); the confirmed rate is a rate, not a
    reputation number."""
    counts = Counter(getattr(e, "determination", None) or (e.get("determination") if isinstance(e, dict) else None)
                     for e in effects)
    counts.pop(None, None)
    total = sum(counts.values())
    return {
        "capability": capability,
        "observations": total,
        "by_determination": dict(counts),
        "confirmed_rate": (counts.get("confirmed", 0) / total) if total else None,
    }
