"""Transport result restraint (proposal 0053; CHP-CORE-022).

A transport moves invocations to a host and results back — it must NEVER fabricate a result, and
transport-level acceptance/liveness is NOT admission or execution. Only the host's governed pipeline
produces admission/execution evidence; the transport returns the host's result verbatim.
"""

import asyncio

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.transport import LocalTransport
from chp_core.types import CapabilityDescriptor, InvocationEnvelope


def _host():
    h = LocalCapabilityHost("t-host", store=SQLiteEvidenceStore(":memory:"))

    async def boom(_ctx, _p):
        raise RuntimeError("handler failed")

    h.register(CapabilityDescriptor(id="c.boom", version="1.0.0", description=""), boom)
    return h


def test_health_is_liveness_not_execution():
    # CHP-CORE-022: a transport health check is liveness — it must NOT be recorded as an execution
    # or admission. Calling it adds no evidence to the store.
    h = _host()
    t = LocalTransport(h)
    before = len(h.store.all())
    snap = asyncio.run(t.health())
    assert snap["status"] == "ok"
    assert len(h.store.all()) == before  # transport acceptance ≠ execution: no evidence emitted


def test_transport_returns_host_result_never_fabricates_success():
    # A failed execution comes back as the host's failure — the transport does not synthesize a
    # success from transport-level delivery.
    h = _host()
    t = LocalTransport(h)
    env = InvocationEnvelope(capability_id="c.boom", version="1.0.0", payload={})
    res = asyncio.run(t.ainvoke_envelope(env))
    assert res.outcome != "success"  # transport delivered; it did not manufacture a result
