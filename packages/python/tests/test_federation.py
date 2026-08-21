"""Market federation policy (federation wave arc 2; CHP-FED-001/002/003/007/009).

The thin policy layer over the existing trust primitives: a MarketDescriptor contract, a per-
requirement federate/prohibit decision (a sensitive capability never leaves the market), ordered
source-priority ranking, and source-market provenance preserved through resolution.
"""

from chp_core import (
    CapabilityRequirement,
    MarketDescriptor,
    ResolvedCandidate,
    federable,
    resolve,
    source_priority_key,
)


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
