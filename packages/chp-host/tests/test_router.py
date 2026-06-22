"""MultiHostRouter: routing table, selection, failover, merged discover, replay."""

from __future__ import annotations

import pytest

from chp_core import HttpTransport, LocalTransport

from chp_host import MultiHostRouter, NoHealthyHostError, UnknownCapabilityError

from ._util import make_echo_host, make_math_host, served


async def _router(*transports, **kwargs) -> MultiHostRouter:
    router = MultiHostRouter(list(transports), **kwargs)
    await router.connect()
    return router


# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------

class TestRoutingTable:
    @pytest.mark.asyncio
    async def test_table_maps_capability_to_owner(self):
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        b = LocalTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
        router = await _router(a, b)
        assert router.hosts_for("cap.a") == ["A"]
        assert router.hosts_for("cap.b") == ["B"]
        assert router.capability_ids == ["cap.a", "cap.b"]

    @pytest.mark.asyncio
    async def test_shared_capability_lists_both_hosts_in_priority_order(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        assert router.hosts_for("echo.who") == ["A", "B"]

    @pytest.mark.asyncio
    async def test_prefer_by_name_routes_to_that_node(self):
        # A is first in priority order, but prefer="B" must win.
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        assert (await router.ainvoke("echo.who", {})).data == {"host": "a"}
        assert (await router.ainvoke("echo.who", {}, prefer="B")).data == {"host": "b"}

    @pytest.mark.asyncio
    async def test_prefer_by_role_routes_to_that_node(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b, host_roles={"A": "compute", "B": "inference"})
        assert (await router.ainvoke("echo.who", {}, prefer="inference")).data == {"host": "b"}

    @pytest.mark.asyncio
    async def test_prefer_falls_back_when_preferred_owner_absent(self):
        # prefer names a node that doesn't own the cap → still routes to an owner.
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        assert (await router.ainvoke("echo.who", {}, prefer="A")).data == {"host": "b"}

    @pytest.mark.asyncio
    async def test_prefer_via_envelope_metadata(self):
        from chp_core import InvocationEnvelope
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        env = InvocationEnvelope(capability_id="echo.who", payload={}, metadata={"prefer": "B"})
        assert (await router.ainvoke_envelope(env)).data == {"host": "b"}

    @pytest.mark.asyncio
    async def test_unreachable_host_skipped_on_connect(self):
        dead = HttpTransport("http://127.0.0.1:1", name="dead")
        live = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(dead, live)
        # Only the live host contributes capabilities.
        assert router.hosts_for("echo.who") == ["B"]


# ---------------------------------------------------------------------------
# Capacity-aware routing (least_loaded)
# ---------------------------------------------------------------------------

class TestCapacityRouting:
    import time as _time

    def _seed(self, router, name, **stats):
        import time
        router._stats_cache[name] = (time.monotonic(), stats)

    @pytest.mark.asyncio
    async def test_routes_to_least_loaded_by_cpu(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b, selection="least_loaded")
        self._seed(router, "A", load_per_core=0.9)
        self._seed(router, "B", load_per_core=0.1)
        assert (await router.ainvoke("echo.who", {})).data == {"host": "b"}  # B less loaded
        # Flip the load → routes to A.
        self._seed(router, "A", load_per_core=0.1)
        self._seed(router, "B", load_per_core=0.9)
        assert (await router.ainvoke("echo.who", {})).data == {"host": "a"}

    @pytest.mark.asyncio
    async def test_inference_routes_by_gpu(self):
        cap = "chp.adapters.local_llm.generate"
        a = LocalTransport(make_echo_host("A", "a", cap_id=cap), name="A")
        b = LocalTransport(make_echo_host("B", "b", cap_id=cap), name="B")
        router = await _router(a, b, selection="least_loaded")
        # A has low CPU but busy GPU; B busy CPU but free GPU. Inference → GPU wins.
        self._seed(router, "A", load_per_core=0.1, gpu={"utilization_pct": 90})
        self._seed(router, "B", load_per_core=0.9, gpu={"utilization_pct": 5})
        assert (await router.ainvoke(cap, {})).data == {"host": "b"}

    @pytest.mark.asyncio
    async def test_affinity_overrides_capacity(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b, selection="least_loaded")
        self._seed(router, "A", load_per_core=0.9)  # A more loaded
        self._seed(router, "B", load_per_core=0.1)
        # Explicit pin beats capacity.
        assert (await router.ainvoke("echo.who", {}, prefer="A")).data == {"host": "a"}

    @pytest.mark.asyncio
    async def test_node_without_stats_sorts_last(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b, selection="least_loaded")
        self._seed(router, "B", load_per_core=0.5)  # only B has stats; A unknown
        assert (await router.ainvoke("echo.who", {})).data == {"host": "b"}


# ---------------------------------------------------------------------------
# Selection policy
# ---------------------------------------------------------------------------

class TestSelection:
    @pytest.mark.asyncio
    async def test_first_wins_by_priority(self):
        a = LocalTransport(make_echo_host("A", "alpha"), name="A")
        b = LocalTransport(make_echo_host("B", "beta"), name="B")
        router = await _router(a, b)  # A has priority
        for _ in range(3):
            result = await router.ainvoke("echo.who", {})
            assert result.data["host"] == "alpha"

    @pytest.mark.asyncio
    async def test_round_robin_alternates(self):
        a = LocalTransport(make_echo_host("A", "alpha"), name="A")
        b = LocalTransport(make_echo_host("B", "beta"), name="B")
        router = await _router(a, b, selection="round_robin")
        served_by = [
            (await router.ainvoke("echo.who", {})).data["host"] for _ in range(4)
        ]
        # Both hosts are exercised across calls.
        assert set(served_by) == {"alpha", "beta"}


# ---------------------------------------------------------------------------
# Invocation errors / failover
# ---------------------------------------------------------------------------

class TestFailover:
    @pytest.mark.asyncio
    async def test_unknown_capability_raises(self):
        router = await _router(LocalTransport(make_math_host(), name="m"))
        with pytest.raises(UnknownCapabilityError):
            await router.ainvoke("nope.missing", {})

    @pytest.mark.asyncio
    async def test_no_healthy_host_raises(self):
        # Build the table while the host is alive, then take it down.
        host = make_echo_host("X", "x")
        with served(host) as url:
            tr = HttpTransport(url, name="X")
            router = await _router(tr)
        # Server is now shut down (context exited) → owner exists but unreachable.
        with pytest.raises(NoHealthyHostError):
            await router.ainvoke("echo.who", {})

    @pytest.mark.asyncio
    async def test_failover_across_two_http_hosts(self):
        # Both hosts serve echo.who; the priority host is killed after connect,
        # and the router must fail over to the live one.
        live_host = make_echo_host("LIVE", "live")
        with served(live_host) as live_url:
            live = HttpTransport(live_url, name="live")
            with served(make_echo_host("DOOMED", "doomed")) as doomed_url:
                doomed = HttpTransport(doomed_url, name="doomed")
                router = await _router(doomed, live)  # doomed has priority
                first = await router.ainvoke("echo.who", {})
                assert first.data["host"] == "doomed"
            # inner context exited → 'doomed' is down; 'live' stays up
            result = await router.ainvoke("echo.who", {})
            assert result.data["host"] == "live"


# ---------------------------------------------------------------------------
# Merged discovery
# ---------------------------------------------------------------------------

class TestMergedDiscover:
    @pytest.mark.asyncio
    async def test_union_of_capabilities(self):
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        b = LocalTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
        router = await _router(a, b)
        merged = await router.discover()
        ids = {c["id"] for c in merged["capabilities"]}
        assert ids == {"cap.a", "cap.b"}
        assert merged["kind"] == "multi-host"
        assert set(merged["hosts"]) == {"A", "B"}

    @pytest.mark.asyncio
    async def test_shared_capability_deduped_and_annotated(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        merged = await router.discover()
        echo = [c for c in merged["capabilities"] if c["id"] == "echo.who"]
        assert len(echo) == 1  # deduped by capability_uri
        assert set(echo[0]["hosts"]) == {"A", "B"}
        assert merged["capability_count"] == 1


# ---------------------------------------------------------------------------
# Stitched cross-host replay
# ---------------------------------------------------------------------------

class TestStitchedReplay:
    @pytest.mark.asyncio
    async def test_replay_merges_events_from_all_hosts(self):
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        b = LocalTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
        router = await _router(a, b)

        corr = {"correlation_id": "shared-xhost"}
        await router.ainvoke("cap.a", {}, correlation=corr)
        await router.ainvoke("cap.b", {}, correlation=corr)

        events = await router.replay("shared-xhost")
        hosts = {e["_host"] for e in events}
        assert hosts == {"A", "B"}  # stitched across both
        # each invoke emits >= 2 events (started + completed)
        assert len(events) >= 4
        # ordered by (timestamp, sequence)
        keys = [(e.get("timestamp", ""), e.get("sequence", 0)) for e in events]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Health aggregate
# ---------------------------------------------------------------------------

class TestHealth:
    @pytest.mark.asyncio
    async def test_all_healthy(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        b = LocalTransport(make_echo_host("B", "b"), name="B")
        router = await _router(a, b)
        health = await router.health()
        assert health["status"] == "ok"
        assert health["healthy_count"] == 2
        assert health["host_count"] == 2

    @pytest.mark.asyncio
    async def test_degraded_when_one_down(self):
        live = LocalTransport(make_echo_host("A", "a"), name="A")
        dead = HttpTransport("http://127.0.0.1:1", name="dead")
        router = await _router(live, dead)
        health = await router.health()
        assert health["status"] == "degraded"
        assert health["healthy_count"] == 1


# ---------------------------------------------------------------------------
# HTTP surface — ainvoke_envelope + replay_result
# ---------------------------------------------------------------------------

class TestRouterHTTPSurface:
    """Verify the methods that let MultiHostRouter serve over HTTP."""

    @pytest.mark.asyncio
    async def test_ainvoke_envelope_delegates(self):
        from chp_core.types import InvocationEnvelope
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        b = LocalTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
        router = await _router(a, b)
        env = InvocationEnvelope(capability_id="cap.a", payload={})
        result = await router.ainvoke_envelope(env)
        assert result.outcome == "success"
        assert result.data == {"host": "a"}

    @pytest.mark.asyncio
    async def test_ainvoke_envelope_accepts_dict(self):
        a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
        router = await _router(a)
        result = await router.ainvoke_envelope({"capability_id": "cap.a", "payload": {}})
        assert result.outcome == "success"

    def test_replay_result_returns_replay_result_type(self):
        import asyncio
        from chp_core.types import ReplayResult

        a = LocalTransport(make_math_host("M"), name="M")

        async def _invoke():
            router = MultiHostRouter([a])
            await router.connect()
            res = await router.ainvoke("math.add", {"a": 1, "b": 2})
            return router, res.correlation.correlation_id

        router, corr_id = asyncio.run(_invoke())
        replay = router.replay_result(corr_id)
        assert isinstance(replay, ReplayResult)
        assert replay.event_count >= 2
        assert hasattr(replay, "to_dict")

    def test_replay_result_accepts_dict_query(self):
        import asyncio
        from chp_core.types import ReplayResult

        a = LocalTransport(make_math_host("M"), name="M")

        async def _invoke():
            router = MultiHostRouter([a])
            await router.connect()
            res = await router.ainvoke("math.add", {"a": 3, "b": 4})
            return router, res.correlation.correlation_id

        router, corr_id = asyncio.run(_invoke())
        replay = router.replay_result({"correlation_id": corr_id})
        assert isinstance(replay, ReplayResult)
        assert replay.correlation_id == corr_id
