"""Claim-scoped trust anchors (CHP-TRUST-001/002).

Trust is local and CLAIM-SCOPED: an issuer trusted to attest one claim type is not thereby trusted
for another. A TrustAnchor names the issuer AND the claim classes it is authoritative for; trust
policy is separate from integrity verification (CHP-VER-011).
"""

import pytest

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
