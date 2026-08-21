"""Keystone conformance test for the dual-digest execution-truth foundation (proposal 0043).

Proves CHP-CORE-004/005/006/007/024 against the package golden vector: the two digests
are distinct, provider substitution keeps action_digest but changes invocation_digest, and
a semantic-input mutation changes action_digest.
"""

from chp_core.digests import action_digest, invocation_digest

# Golden vector H1-action-invocation-digests-v0.3, inlined so the test is self-contained
# and portable to public chp-core (the package's docs/ vector file is not mirrored there).
# Source: docs/product/.../07_conformance/vectors/h1_digest_vector.json.
_ARTIFACT = "sha256:" + "a" * 64
_ACTION_DIGEST = "sha256:ce508e34180d1cc0906b2d7212e2c9a96d7de555db063e8c11a61a3e3786eb61"
_INVOCATION_DIGEST = "sha256:e2da005d35ea205964826a6cf6425a79733afe094b73aaa7f5802b60752cad26"


def test_matches_golden_vector():
    assert (
        action_digest(
            capability={"id": "org.capabilityhostprotocol.professional.review", "version": "1.0.0"},
            principal={"id": "urn:chp:entity:acme"},
            action_input={"artifact_digest": _ARTIFACT},
            semantic_context={"jurisdiction": "CA-ON"},
        )
        == _ACTION_DIGEST
    )
    assert (
        invocation_digest(
            invocation_id="inv_h1_001",
            action_digest=_ACTION_DIGEST,
            actor={"id": "urn:chp:entity:agent-legal-1"},
            principal={"id": "urn:chp:entity:acme"},
            binding={"id": "binding_jane_review_1", "version": "1"},
            provider={"id": "urn:chp:entity:jane"},
            host={"id": "urn:chp:entity:market-managed-host"},
            governance_context={},
        )
        == _INVOCATION_DIGEST
    )


def test_provider_substitution_keeps_action_changes_invocation():
    # CHP-CORE-006/007: provider jane -> john → action unchanged, invocation changed.
    a = dict(
        capability={"id": "c", "version": "1.0.0"},
        principal={"id": "p"},
        action_input={"x": "1"},
        semantic_context={},
    )
    ad = action_digest(**a)
    base = dict(
        invocation_id="inv1",
        action_digest=ad,
        actor={"id": "a"},
        principal={"id": "p"},
        binding={"id": "b", "version": "1"},
        host={"id": "h"},
        governance_context={},
    )
    assert ad == action_digest(**a)  # action_digest stable under recomputation
    assert invocation_digest(provider={"id": "jane"}, **base) != invocation_digest(
        provider={"id": "john"}, **base
    )


def test_semantic_mutation_changes_action():
    # CHP-CORE-006: artifact-digest change → action_digest changes.
    base = dict(
        capability={"id": "c", "version": "1.0.0"},
        principal={"id": "p"},
        semantic_context={},
    )
    assert action_digest(action_input={"artifact_digest": "sha256:aaaa"}, **base) != action_digest(
        action_input={"artifact_digest": "sha256:bbbb"}, **base
    )


def test_evidence_records_stable_action_digest():
    """Host stamps action_digest into evidence (proposal 0043): constant across all
    events of an invocation and across host identity (CHP-CORE-004), changing only on a
    semantic-input mutation (CHP-CORE-006)."""
    import asyncio

    from chp_core import (
        CapabilityDescriptor,
        CorrelationContext,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    async def handler(_ctx, _payload):
        return {"ok": True}

    def make_host(host_id: str) -> LocalCapabilityHost:
        h = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))
        h.register(CapabilityDescriptor(id="svc.do", version="1.0.0", description="x"), handler)
        return h

    async def digests_for(host: LocalCapabilityHost, payload: dict) -> list[str]:
        await host.ainvoke("svc.do", payload, correlation=CorrelationContext(correlation_id="c"))
        return [e["action_digest"] for e in host.replay("c") if e.get("action_digest")]

    dA = asyncio.run(digests_for(make_host("host-A"), {"amount": "10"}))
    dB = asyncio.run(digests_for(make_host("host-B"), {"amount": "10"}))
    dC = asyncio.run(digests_for(make_host("host-C"), {"amount": "20"}))

    assert dA and dB and dC                 # every event carries the digest
    assert len(set(dA)) == 1                # constant across an invocation's events
    assert set(dA) == set(dB)               # host identity does NOT change action_digest
    assert set(dA) != set(dC)               # semantic input change DOES


def test_invocation_digest_routing_and_self_hosted_default():
    """Host stamps invocation_digest (proposal 0043): present by default via a
    synthesized self-hosted binding; with invocation_id held fixed, swapping the
    resolved binding's provider changes invocation_digest (CHP-CORE-005/007) while
    action_digest stays constant (CHP-CORE-004)."""
    import asyncio

    from chp_core import (
        CapabilityBinding,
        CapabilityDescriptor,
        CorrelationContext,
        InvocationEnvelope,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    async def handler(_ctx, _payload):
        return {"ok": True}

    def make_host() -> LocalCapabilityHost:
        h = LocalCapabilityHost("host-A", store=SQLiteEvidenceStore(":memory:"))
        h.register(CapabilityDescriptor(id="svc.do", version="1.0.0", description="x"), handler)
        return h

    def bind(provider_id: str) -> dict:
        return CapabilityBinding(
            id=f"binding_{provider_id}",
            version="1",
            capability={"id": "svc.do", "version": "1.0.0"},
            provider={"id": provider_id},
            host={"id": "host-A"},
        ).to_dict()

    async def run(corr: str, binding: dict | None, inv_id: str) -> tuple[list[str], list[str]]:
        host = make_host()
        env = InvocationEnvelope(
            invocation_id=inv_id,
            capability_id="svc.do",
            version="1.0.0",
            payload={"amount": "10"},
            correlation=CorrelationContext(correlation_id=corr),
            binding=binding,
        )
        await host.ainvoke_envelope(env)
        evs = host.replay(corr)
        return (
            [e["action_digest"] for e in evs if e.get("action_digest")],
            [e["invocation_digest"] for e in evs if e.get("invocation_digest")],
        )

    a_jane, i_jane = asyncio.run(run("c1", bind("jane"), "inv-fixed"))
    a_john, i_john = asyncio.run(run("c2", bind("john"), "inv-fixed"))
    _, i_self = asyncio.run(run("c3", None, "inv-self"))

    assert i_jane and i_john and i_self          # invocation_digest present in all three
    assert len(set(i_jane)) == 1                 # constant across an invocation's events
    assert set(a_jane) == set(a_john)            # provider swap keeps action_digest
    assert set(i_jane) != set(i_john)            # provider swap changes invocation_digest
    assert set(i_self) != set(i_jane)            # self-hosted binding is distinct


def test_capability_binding_roundtrip():
    from chp_core import CapabilityBinding

    d = {
        "id": "b1",
        "version": "1",
        "capability": {"id": "c", "version": "1.0.0"},
        "provider": {"id": "p"},
        "host": {"id": "h"},
    }
    assert CapabilityBinding.from_mapping(d).to_dict() == d
