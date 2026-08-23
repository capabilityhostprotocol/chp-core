"""Protocol-core hardening — the prohibition/proving tests for CORE partials.

The mechanisms already hold; these tests pin the normative MUSTs so the rows can't silently
regress: an Invocation's identity changes iff a governance-relevant field changes (CORE-003), NO
public invoke entrypoint reaches a handler past a policy denial (CORE-018, no ungoverned bypass), and
a stable idempotency key dedupes a repeated invocation (CORE-023).
"""

import asyncio

import pytest
from chp_core import (
    CapabilityDescriptor,
    CorrelationContext,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core.digests import invocation_digest
from chp_core.policy import PolicyConfig
from chp_core.types import InvocationEnvelope

_AD = "sha256:" + "a" * 64


def _routing(**over):
    base = dict(invocation_id="inv-1", action_digest=_AD, actor={"id": "act"},
                principal={"id": "p"}, binding={"id": "b1"}, provider={"id": "prov"}, host={"id": "h"})
    base.update(over)
    return base


def test_invocation_immutable_identity_governance_change_rekeys():
    # CHP-CORE-003: an Invocation is immutable once created — its identity (invocation_digest) is a
    # deterministic function of its governed fields, and a governance-relevant change produces a NEW
    # identity (so an in-place rewrite could never pass unnoticed as the same invocation).
    d1 = invocation_digest(**_routing())
    assert d1 == invocation_digest(**_routing())                       # deterministic / stable
    assert d1 != invocation_digest(**_routing(binding={"id": "b2"}))   # routing change → new identity
    assert d1 != invocation_digest(**_routing(provider={"id": "other"}))
    assert d1 != invocation_digest(**_routing(host={"id": "h2"}))


async def _collect_stream(host, env):
    result, chunks = None, []
    async for item in host.ainvoke_stream(env):
        if "chunk" in item:
            chunks.append(item["chunk"])
        if "result" in item:
            result = item["result"]
    return result, chunks


def test_no_ungoverned_bypass_across_every_invoke_path():
    # CHP-CORE-018: a policy-blocked capability is denied identically through BOTH public invoke
    # entrypoints (sync + stream), and the handler is never reached on either — no bypass path.
    ran = {"count": 0}

    async def handler(_ctx, _payload):
        ran["count"] += 1
        return {"ok": True}

    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"),
                               policy=PolicyConfig(block_capability_ids=["svc.blocked"]))
    host.register(CapabilityDescriptor(id="svc.blocked", version="1.0.0", description="x"), handler)

    async def go():
        env = InvocationEnvelope(capability_id="svc.blocked", invocation_id="inv-b1", payload={})
        r_sync = await host.ainvoke_envelope(env)
        r_stream, chunks = await _collect_stream(
            host, InvocationEnvelope(capability_id="svc.blocked", invocation_id="inv-b2", payload={}))
        return r_sync, r_stream, chunks

    r_sync, r_stream, chunks = asyncio.run(go())
    assert r_sync.outcome == "denied" and r_sync.denial.code == "policy_blocked"
    assert r_stream.outcome == "denied" and r_stream.denial.code == "policy_blocked"
    assert chunks == []            # a denied stream emits no chunk before the terminal result
    assert ran["count"] == 0       # the handler was never reached on either path


def test_stable_idempotency_key_dedupes_repeat_invocation():
    # CHP-CORE-023: a stable idempotency key (the invocation_id carried to a host's Gate 0) makes a
    # repeated invocation replay its recorded result instead of re-running the side effect — the same
    # dedupe a downstream host performs when the key is propagated to it.
    ran = {"count": 0}

    async def handler(_ctx, _payload):
        ran["count"] += 1
        return {"n": ran["count"]}

    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="svc.pay", version="1.0.0", description="x"), handler)

    async def go():
        env = InvocationEnvelope(capability_id="svc.pay", invocation_id="idem-key-1", payload={"amt": 10})
        first = await host.ainvoke_envelope(env)
        # same idempotency key again (a client retry / a downstream re-delivery)
        second = await host.ainvoke_envelope(
            InvocationEnvelope(capability_id="svc.pay", invocation_id="idem-key-1", payload={"amt": 10}))
        return first, second

    first, second = asyncio.run(go())
    assert first.outcome == "success" and not first.replayed
    assert second.outcome == "success" and second.replayed          # Gate 0 replayed the recorded result
    assert second.data == first.data                                # identical, not a second execution
    assert ran["count"] == 1                                        # the side effect ran exactly once


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
