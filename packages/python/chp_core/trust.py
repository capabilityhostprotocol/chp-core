"""Claim-scoped trust anchors — TrustAnchor + anchored_issuer_trusted (CHP-TRUST-001/002).

Trust in CHP is LOCAL and SCOPED: a relying party trusts an issuer for a specific class of claims,
never "trust this issuer for everything". A ``TrustAnchor`` is that scoped declaration — it names the
issuer AND the claim classes it is authoritative for. An issuer trusted to attest identity is NOT
thereby trusted to attest a professional licence unless an anchor says so.

This is trust POLICY the relying party configures, not a global fact: there is no canonical authority
(CHP-TRUST-010, CHP-FED-005), and integrity verification stays separate from this trust decision
(CHP-VER-011). ``anchored_issuer_trusted`` answers only "does my local policy trust this issuer for
this claim type" — the caller still verifies the assertion's integrity independently.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .types import JSON, new_id


@dataclass(slots=True)
class TrustAnchor:
    """A relying party's trust root SCOPED to the claim classes it is authoritative for
    (CHP-TRUST-002). ``claim_types`` lists the claim type ids this anchor covers; the wildcard
    ``"*"`` means all claim types (use sparingly — it is the flat-trust escape hatch)."""

    issuer: str
    claim_types: list[str]
    id: str = field(default_factory=lambda: new_id("anchor"))

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("a trust anchor must name an issuer")
        if not self.claim_types:
            raise ValueError("a trust anchor must scope at least one claim type ('*' for all)")

    def trusts(self, issuer: str, claim_type: str) -> bool:
        """Whether THIS anchor trusts ``issuer`` for ``claim_type`` — the issuer must match AND the
        claim type must be in the anchor's scope (or the anchor is a wildcard)."""
        return issuer == self.issuer and ("*" in self.claim_types or claim_type in self.claim_types)

    def to_dict(self) -> JSON:
        return asdict(self)


def anchored_issuer_trusted(anchors: list[TrustAnchor], issuer: str, claim_type: str) -> bool:
    """Whether ANY of the relying party's anchors trusts ``issuer`` for ``claim_type``
    (CHP-TRUST-001/002). Trust is claim-scoped: an issuer trusted for one claim type is NOT trusted
    for another unless an anchor names it. Integrity verification is separate (CHP-VER-011) — this
    answers trust policy only, never whether the assertion is authentic or true."""
    return any(a.trusts(issuer, claim_type) for a in anchors)


def verified_supply(entities: list, *, trusted_issuers: frozenset) -> JSON:
    """Distinguish INDEPENDENTLY VERIFIED supply from a raw entity count (CHP-SEC-003).

    An entity counts as VERIFIED iff at least one of its identifiers is vouched for by an issuer the
    relying policy trusts (an ``issuer`` in ``trusted_issuers``). Returns {total, verified, unverified,
    independent_verified} where ``independent_verified`` dedupes by vouching issuer — so a flood of
    unverified sybil entities inflates ``total`` (and, from one captured issuer, ``verified``) but NOT
    ``independent_verified``. A public-market profile weights/thresholds on the verified counts rather
    than raw registrations, making mass unverified creation distinguishable from real verified supply.
    """
    total = verified = 0
    issuers: set = set()
    for e in entities:
        total += 1
        ids = getattr(e, "identifiers", None)
        if ids is None and isinstance(e, dict):
            ids = e.get("identifiers")
        vouchers = {i.get("issuer") for i in (ids or []) if i.get("issuer") in trusted_issuers}
        if vouchers:
            verified += 1
            issuers |= vouchers
    return {"total": total, "verified": verified, "unverified": total - verified,
            "independent_verified": len(issuers)}
