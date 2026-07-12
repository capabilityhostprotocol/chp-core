"""Gateway exactly-once (chp-v0.2.md §13.2, proposal 0014): the router's
cross-owner result cache keyed by the client's invocation_id."""

from __future__ import annotations

import asyncio

from chp_core import LocalCapabilityHost, LocalTransport, SQLiteEvidenceStore
from chp_core.decorators import capability
from chp_host import MultiHostRouter


def _counting_host(host_id: str, calls: list) -> LocalCapabilityHost:
    @capability(id="x.do", version="1.0.0", description="Count executions.")
    def do() -> dict:  # type: ignore[return-value]
        calls.append(host_id)
        return {"host": host_id, "n": len(calls)}

    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))
    host.register(do)
    return host


def _router(*hosts, store) -> MultiHostRouter:
    router = MultiHostRouter([LocalTransport(h, name=h.host_id) for h in hosts], store=store)
    asyncio.run(router.connect())
    return router


def _invoke(router, inv_id=None):
    return asyncio.run(router.ainvoke("x.do", {}, invocation_id=inv_id))


def test_retried_id_replays_at_gateway_no_owner_execution():
    calls: list = []
    store = SQLiteEvidenceStore(":memory:")
    router = _router(_counting_host("owner-a", calls), store=store)

    r1 = _invoke(router, "inv-1")
    assert r1.replayed is False and len(calls) == 1  # owner executed once

    r2 = _invoke(router, "inv-1")  # retry the SAME client id
    assert r2.replayed is True                       # gateway replayed
    assert len(calls) == 1, "the owner MUST NOT execute again"
    assert r2.data == r1.data                        # identical served result


def test_fresh_id_each_call_executes():
    calls: list = []
    store = SQLiteEvidenceStore(":memory:")
    router = _router(_counting_host("owner-a", calls), store=store)
    _invoke(router, None)  # no invocation_id → per-call, un-cacheable
    _invoke(router, None)
    assert len(calls) == 2, "distinct (minted) ids each execute"


def test_definitive_result_cached_denial_not():
    calls: list = []
    store = SQLiteEvidenceStore(":memory:")
    router = _router(_counting_host("owner-a", calls), store=store)

    _invoke(router, "inv-ok")
    assert isinstance(store.lookup_result("inv-ok"), dict)  # success cached

    # unknown capability → capability_not_found denial; MUST NOT be cached
    denied = asyncio.run(router.ainvoke("no.such", {}, invocation_id="inv-deny"))
    assert denied.outcome == "denied" and denied.denial.code == "capability_not_found"
    assert store.lookup_result("inv-deny") is None, "a routing denial must not be cached"


def test_first_write_wins():
    """A racing duplicate replays the first result, never overwrites it."""
    calls: list = []
    store = SQLiteEvidenceStore(":memory:")
    router = _router(_counting_host("owner-a", calls), store=store)
    r1 = _invoke(router, "inv-race")
    # manually attempt to overwrite → INSERT OR IGNORE keeps the first
    store.record_result("inv-race", {"invocation_id": "inv-race", "outcome": "success",
                                      "success": True, "data": {"forged": True}})
    r2 = _invoke(router, "inv-race")
    assert r2.data == r1.data and r2.data.get("forged") is None
