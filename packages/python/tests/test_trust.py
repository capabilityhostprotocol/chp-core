"""Claim-scoped trust anchors (CHP-TRUST-001/002).

Trust is local and CLAIM-SCOPED: an issuer trusted to attest one claim type is not thereby trusted
for another. A TrustAnchor names the issuer AND the claim classes it is authoritative for; trust
policy is separate from integrity verification (CHP-VER-011).
"""

import pytest

from chp_core.assertions import Assertion, conflicting_assertions, independent_sources
from chp_core.trust import TrustAnchor, anchored_issuer_trusted


def test_anchor_is_claim_scoped():
    bar = TrustAnchor(issuer="urn:chp:issuer:bar", claim_types=["chp.identity.licence"])
    # trusted for the scoped claim type...
    assert bar.trusts("urn:chp:issuer:bar", "chp.identity.licence")
    # ...but NOT for a different claim type (no flat "trust this issuer for everything")
    assert not bar.trusts("urn:chp:issuer:bar", "chp.identity.credit_score")
    # ...and never for a different issuer
    assert not bar.trusts("urn:chp:issuer:other", "chp.identity.licence")


def test_wildcard_anchor_covers_all_claim_types():
    root = TrustAnchor(issuer="urn:chp:issuer:root", claim_types=["*"])
    assert root.trusts("urn:chp:issuer:root", "anything.at.all")


def test_anchored_issuer_trusted_across_a_policy_set():
    anchors = [
        TrustAnchor(issuer="urn:chp:issuer:bar", claim_types=["chp.identity.licence"]),
        TrustAnchor(issuer="urn:chp:issuer:dmv", claim_types=["chp.identity.driving"]),
    ]
    assert anchored_issuer_trusted(anchors, "urn:chp:issuer:bar", "chp.identity.licence")
    # the dmv is trusted for driving, NOT for a licence — claim scoping across the policy set
    assert not anchored_issuer_trusted(anchors, "urn:chp:issuer:dmv", "chp.identity.licence")
    assert not anchored_issuer_trusted([], "urn:chp:issuer:bar", "chp.identity.licence")


def test_anchor_rejects_empty_scope():
    with pytest.raises(ValueError):
        TrustAnchor(issuer="x", claim_types=[])
    with pytest.raises(ValueError):
        TrustAnchor(issuer="", claim_types=["*"])


def test_verified_supply_distinguishes_anchored_from_sybil():
    # CHP-SEC-003: verified supply (entities vouched by a trusted issuer) is distinguishable from a
    # raw entity count, and independent_verified dedupes a sybil flood from one captured issuer.
    from chp_core import EntitySubject, verified_supply
    trusted = frozenset({"issuer-good"})
    real = EntitySubject(id="e1", kind="org",
                         identifiers=[{"kind": "domain", "value": "acme.com", "issuer": "issuer-good"}])
    sybil1 = EntitySubject(id="s1", kind="org", identifiers=[{"kind": "email", "value": "a@x"}])
    sybil2 = EntitySubject(id="s2", kind="org", identifiers=[{"kind": "email", "value": "b@x"}])
    s = verified_supply([real, sybil1, sybil2], trusted_issuers=trusted)
    assert s == {"total": 3, "verified": 1, "unverified": 2, "independent_verified": 1}
    # a flood all vouched by ONE captured issuer inflates 'verified' but not 'independent_verified'
    flood = [EntitySubject(id=f"f{i}", kind="org",
                           identifiers=[{"kind": "x", "value": str(i), "issuer": "issuer-good"}])
             for i in range(5)]
    f = verified_supply(flood, trusted_issuers=trusted)
    assert f["verified"] == 5 and f["independent_verified"] == 1


def _asrt(claim_type, issuer, value):
    return Assertion(claim_type=claim_type, issuer={"id": issuer}, subject={"kind": "org", "id": "lex"}, value=value)


def test_rggov_conflicts_preserved_via_the_assertions_primitive():
    # RG-GOV "conflicts": the trust profile reuses chp_core.assertions.conflicting_assertions (CHP-TRUST-008) —
    # two distinct issuers disagreeing on a claim is PRESERVED, never adjudicated to a winner.
    conflicts = conflicting_assertions([
        _asrt("disciplinary_status", "urn:law-society", "clear"),
        _asrt("disciplinary_status", "urn:complaints-board", "under_review"),
        _asrt("good_standing", "urn:law-society", "good")])
    assert len(conflicts) == 1
    assert set(conflicts[0]["values"]) == {"clear", "under_review"}   # both kept, not collapsed


def test_rggov_independent_corroboration_via_the_assertions_primitive():
    # RG-GOV "local trust"/source-independence: independent_sources (CHP-TRUST-006) dedupes by issuer, so the
    # same source twice corroborates once — inflation by re-projection is prevented.
    items = [{"issuer": "urn:law-society"}, {"issuer": "urn:court-registry"}, {"issuer": "urn:law-society"}]
    assert independent_sources(items, key=lambda i: i["issuer"]) == 2


def test_no_evidence_laundering_trust_keys_on_original_issuer():
    # CHP-TRUST-005: a relaying/re-signing party cannot launder foreign evidence into trust — the trust
    # decision keys on the ORIGINAL issuer's anchor, not whoever relayed it. Trusting a relay for its own
    # attestations does NOT extend trust to a foreign issuer's claim the relay merely forwards.
    anchors = [TrustAnchor(issuer="urn:trusted-relay", claim_types=["*"])]
    assert anchored_issuer_trusted(anchors, "urn:trusted-relay", "chp.identity.licence")   # the relay itself
    assert not anchored_issuer_trusted(anchors, "urn:foreign-issuer", "chp.identity.licence")  # not laundered
