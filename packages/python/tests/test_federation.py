"""Market federation policy (federation wave arc 2; CHP-FED-001/002/003/004/007/008/009).

The thin policy layer over the existing trust primitives: a MarketDescriptor contract, a per-
requirement federate/prohibit decision (a sensitive capability never leaves the market), ordered
source-priority ranking, source-market provenance preserved through resolution, LOCAL reverification of
federated evidence (trust is never inherited across the boundary), and poisoning resistance (the source +
issuer context is preserved so manipulated/foreign federated supply is detectable).
"""

from chp_core import (
    CapabilityRequirement,
    MarketDescriptor,
    ResolvedCandidate,
    federable,
    resolve,
    source_priority_key,
)
from chp_core.trust import TrustAnchor, anchored_issuer_trusted


def _desc(**kw):
    base = dict(market_id="acme-market", federates=True)
    base.update(kw)
    return MarketDescriptor(**base)


# ---- FED-002: MarketDescriptor contract ----

def test_market_descriptor_declares_policy_only():
    d = _desc(source_priority=["internal", "partners"], sensitive_capabilities=["legal.privileged"],
              trusted_issuers=["urn:chp:issuer:bar"])
    out = d.to_dict()
    assert out["market_id"] == "acme-market" and out["federates"] is True
    assert out["source_priority"] == ["internal", "partners"]
    assert out["sensitive_capabilities"] == ["legal.privileged"]


# ---- FED-001 / FED-007: selective federation + sensitive-capability prohibition ----

def test_sensitive_capability_is_prohibited_from_federating():
    d = _desc(sensitive_capabilities=["legal.privileged"])
    ok = CapabilityRequirement(capability={"id": "doc.summarize"})
    sensitive = CapabilityRequirement(capability={"id": "legal.privileged"})
    assert federable(ok, d) is True                 # a normal requirement may federate
    assert federable(sensitive, d) is False         # a sensitive one MUST NOT (FED-007)


def test_non_federating_market_federates_nothing():
    d = _desc(federates=False)
    assert federable(CapabilityRequirement(capability={"id": "doc.summarize"}), d) is False


# ---- FED-009: ordered source priority ----

def test_source_priority_orders_internal_first_unknown_last():
    d = _desc(source_priority=["internal", "partners"])
    internal = ResolvedCandidate(binding={"id": "b1"}, source_market={"id": "internal"})
    partner = ResolvedCandidate(binding={"id": "b2"}, source_market={"id": "partners"})
    public = ResolvedCandidate(binding={"id": "b3"}, source_market={"id": "public"})  # unlisted
    keys = [source_priority_key(c, d) for c in (public, internal, partner)]
    assert keys == [2, 0, 1]  # unlisted sorts last; internal first
    # usable as a ranking key (never overrides hard constraints — that's resolve()'s job)
    assert sorted([public, internal, partner], key=lambda c: source_priority_key(c, d))[0] is internal


# ---- FED-003: source-market provenance preserved through resolution ----

def test_resolution_preserves_source_market_provenance():
    req = CapabilityRequirement(capability={"id": "doc.summarize"}, hard=["h"])
    c = ResolvedCandidate(binding={"id": "b1"}, satisfied_hard=["h"], score=1,
                          source_market={"id": "partners", "registry": "reg-1"})
    res = resolve(req, [c])
    assert res.result == "resolved"
    assert res.candidates[0]["source_market"] == {"id": "partners", "registry": "reg-1"}


def test_resolution_omits_source_market_when_absent():
    req = CapabilityRequirement(capability={"id": "x"}, hard=["h"])
    res = resolve(req, [ResolvedCandidate(binding={"id": "b"}, satisfied_hard=["h"])])
    assert "source_market" not in res.candidates[0]


# ---- FED-004: local reverification (a receiving market never inherits source-market trust) ----

def test_receiving_market_applies_local_trust_not_source_trust():
    # CHP-FED-004: federated evidence is re-verified against the RECEIVING market's OWN trust anchors, never
    # by inheriting the source market's trust. A candidate the source vouches for, issued by a foreign issuer
    # the receiver does not anchor, does NOT become trusted just by crossing the federation boundary (INV-12).
    receiver_anchors = [TrustAnchor(issuer="urn:local-bar", claim_types=["chp.identity.licence"])]
    assert not anchored_issuer_trusted(receiver_anchors, "urn:foreign-bar", "chp.identity.licence")
    # the SAME claim from an issuer the receiver DOES anchor re-verifies as trusted under LOCAL policy
    assert anchored_issuer_trusted(receiver_anchors, "urn:local-bar", "chp.identity.licence")
    # claim-scoping holds across the boundary too: a locally-anchored issuer is not trusted for other claims
    assert not anchored_issuer_trusted(receiver_anchors, "urn:local-bar", "chp.identity.clearance")


# ---- FED-008: federation poisoning resistance (source + verification context preserved) ----

def test_federated_supply_preserves_source_and_issuer_context_for_poisoning_detection():
    # CHP-FED-008: the receiving system preserves the SOURCE + issuer context through resolution, so a
    # manipulated/foreign federated candidate is DETECTABLE: local reverification (FED-004) rejects an
    # unanchored issuer, and the preserved source_market (FED-003) lets a resolver see where a candidate
    # actually came from rather than an origin it merely claims.
    receiver_anchors = [TrustAnchor(issuer="urn:local-bar", claim_types=["*"])]
    req = CapabilityRequirement(capability={"id": "doc.review"}, hard=["h"])
    poisoned = ResolvedCandidate(binding={"id": "b-sybil", "issuer": "urn:sybil-issuer"},
                                 satisfied_hard=["h"], score=9,        # a flattering self-reported score
                                 source_market={"id": "market-unknown"})
    res = resolve(req, [poisoned])
    # provenance is preserved end to end — the receiver sees the true source, not a stripped/forged one
    assert res.candidates[0]["source_market"] == {"id": "market-unknown"}
    # and trust is NOT inherited: the sybil issuer re-verifies to untrusted under local policy
    assert not anchored_issuer_trusted(receiver_anchors, "urn:sybil-issuer", "chp.identity.licence")
