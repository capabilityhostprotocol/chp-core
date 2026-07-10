"""MultiHostRouter: routing table, selection, failover, merged discover, replay."""

from __future__ import annotations

import asyncio

import pytest

from chp_core import HttpTransport, LocalTransport

from chp_host import MultiHostRouter

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
    async def test_unknown_capability_is_processed_denial(self):
        # Spec §11: unknown mesh-wide is a PROCESSED capability_not_found
        # denial, not a raise (was UnknownCapabilityError before v0.2.4).
        router = await _router(LocalTransport(make_math_host(), name="m"))
        result = await router.ainvoke("nope.missing", {})
        assert result.outcome == "denied"
        assert result.denial.code == "capability_not_found"
        assert result.denial.retryable is False

    @pytest.mark.asyncio
    async def test_all_owners_down_is_host_unreachable_denial(self):
        # Build the table while the host is alive, then take it down.
        host = make_echo_host("X", "x")
        with served(host) as url:
            tr = HttpTransport(url, name="X")
            router = await _router(tr)
        # Server is now shut down (context exited) → owner exists but unreachable.
        # Spec §11: a PROCESSED host_unreachable denial (was NoHealthyHostError).
        result = await router.ainvoke("echo.who", {})
        assert result.outcome == "denied"
        assert result.denial.code == "host_unreachable"
        assert result.denial.retryable is True
        assert result.denial.details["attempted_hosts"] == ["X"]
        assert result.denial.details["retry_after_s"] > 0

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

    def test_replay_discloses_unreachable_members(self):
        """A federated replay is never silently partial (binding §4b)."""

        class DeadReplayTransport(LocalTransport):
            async def replay_result(self, query):
                raise ConnectionError("member down")

        async def setup():
            a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
            b = DeadReplayTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
            router = await _router(a, b)
            await router.ainvoke("cap.a", {}, correlation={"correlation_id": "partial-corr"})
            return router

        router = asyncio.run(setup())
        result = router.replay_result("partial-corr")
        assert result.partial is True
        assert result.missing_hosts == ["B"]
        assert {e["_host"] for e in result.events} == {"A"}
        d = result.to_dict()
        assert d["partial"] is True and d["missing_hosts"] == ["B"]

    def test_replay_full_mesh_not_partial(self):
        async def setup():
            a = LocalTransport(make_echo_host("A", "a", cap_id="cap.a"), name="A")
            b = LocalTransport(make_echo_host("B", "b", cap_id="cap.b"), name="B")
            router = await _router(a, b)
            await router.ainvoke("cap.a", {}, correlation={"correlation_id": "full-corr"})
            return router

        router = asyncio.run(setup())
        result = router.replay_result("full-corr")
        assert result.partial is False and result.missing_hosts == []


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


# ---------------------------------------------------------------------------
# Data-path key-pin check (chp-v0.2.md §3.2 / mesh trust)
# ---------------------------------------------------------------------------

class TestDataPathPinCheck:
    def _mesh_with_pin(self, tmp_path, monkeypatch, url, key_id, public_key):
        import json as _json
        monkeypatch.setenv("HOME", str(tmp_path))  # mesh_path() reads HOME at call time
        mesh_dir = tmp_path / ".chp"
        mesh_dir.mkdir(parents=True, exist_ok=True)
        (mesh_dir / "mesh.json").write_text(_json.dumps({
            "name": "mesh",
            "agent_remotes": [{"url": url, "key_id": key_id, "public_key": public_key, "trust": "tofu"}],
        }))

    def _served_signed_host(self, tmp_path, monkeypatch):
        from chp_core import signing
        monkeypatch.setattr(signing, "DEFAULT_KEY_DIR", tmp_path / "hostkeys")
        key = signing.generate_keypair(tmp_path / "hostkeys")
        return key

    def test_pin_mismatch_refuses_member(self, tmp_path, monkeypatch):
        from ._util import served
        key = self._served_signed_host(tmp_path, monkeypatch)
        host = make_echo_host("pinned-host", "p", cap_id="cap.pin")
        with served(host) as url:
            # Pin a DIFFERENT key for this member — impersonation scenario.
            self._mesh_with_pin(tmp_path, monkeypatch, url, "deadbeefdeadbeef", "AAAA")
            router = asyncio.run(MultiHostRouter([HttpTransport(url, name="M")]).connect())
            assert "cap.pin" not in router.capability_ids

    def test_pin_match_allows_member(self, tmp_path, monkeypatch):
        from ._util import served
        key = self._served_signed_host(tmp_path, monkeypatch)
        host = make_echo_host("pinned-host", "p", cap_id="cap.pin")
        with served(host) as url:
            self._mesh_with_pin(tmp_path, monkeypatch, url, key.key_id, key.public_key_b64)
            router = asyncio.run(MultiHostRouter([HttpTransport(url, name="M")]).connect())
            assert "cap.pin" in router.capability_ids

    def test_unpinned_member_gets_pinned_tofu(self, tmp_path, monkeypatch):
        import json as _json
        from ._util import served
        key = self._served_signed_host(tmp_path, monkeypatch)
        host = make_echo_host("pinned-host", "p", cap_id="cap.pin")
        with served(host) as url:
            self._mesh_with_pin(tmp_path, monkeypatch, url, None, None)
            # strip the empty pin fields so it's a fresh remote
            mesh_file = tmp_path / ".chp" / "mesh.json"
            data = _json.loads(mesh_file.read_text())
            data["agent_remotes"] = [{"url": url}]
            mesh_file.write_text(_json.dumps(data))
            router = asyncio.run(MultiHostRouter([HttpTransport(url, name="M")]).connect())
            assert "cap.pin" in router.capability_ids
            pinned = _json.loads(mesh_file.read_text())["agent_remotes"][0]
            assert pinned["key_id"] == key.key_id  # TOFU pin recorded on the data path


# ---------------------------------------------------------------------------
# Routing evidence (spec §11, proposal 0003)
# ---------------------------------------------------------------------------

class TestRoutingEvidence:
    """With a store, routing denials + health transitions land on the gateway's
    own chain — transition-gated, correlation-linked, replay-merged."""

    def _store(self):
        from chp_core.store import SQLiteEvidenceStore
        return SQLiteEvidenceStore(":memory:")

    @pytest.mark.asyncio
    async def test_unreachable_denial_is_evidence_on_gateway_chain(self):
        host = make_echo_host("X", "x")
        store = self._store()
        with served(host) as url:
            router = MultiHostRouter([HttpTransport(url, name="X")], store=store)
            await router.connect()
        result = await router.ainvoke(
            "echo.who", {}, correlation={"correlation_id": "corr-down"})
        assert result.denial.code == "host_unreachable"
        events = store.by_correlation("corr-down")
        types = [e["event_type"] for e in events]
        # the failover mark AND the denial ride the invocation's correlation
        assert "host_marked_unhealthy" in types
        assert "execution_denied" in types
        denied = next(e for e in events if e["event_type"] == "execution_denied")
        assert denied["denial"]["code"] == "host_unreachable"
        assert denied["host_id"] == "chp-gateway"

    @pytest.mark.asyncio
    async def test_health_events_are_transition_gated(self):
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        store = self._store()
        router = MultiHostRouter([a], store=store)
        await router.connect()
        # repeated successes on a healthy host emit NOTHING
        for _ in range(3):
            await router.ainvoke("echo.who", {})
        assert store.by_correlation(f"routing-{router._host_id}") == []
        # repeated failure marks emit exactly ONE unhealthy event
        router._mark_unhealthy(a)
        router._mark_unhealthy(a)
        events = store.by_correlation(f"routing-{router._host_id}")
        assert [e["event_type"] for e in events] == ["host_marked_unhealthy"]
        # recovery emits exactly ONE healthy event
        router._mark_healthy(a)
        router._mark_healthy(a)
        events = store.by_correlation(f"routing-{router._host_id}")
        assert [e["event_type"] for e in events] == [
            "host_marked_unhealthy", "host_marked_healthy"]

    @pytest.mark.asyncio
    async def test_recovery_after_recheck_window_is_observable(self):
        # The unhealthy entry must survive the recheck window so the eventual
        # SUCCESS emits host_marked_healthy (the transition needs prior state).
        a = LocalTransport(make_echo_host("A", "a"), name="A")
        store = self._store()
        router = MultiHostRouter([a], store=store, recheck_interval=0.0)
        await router.connect()
        router._mark_unhealthy(a)
        assert router._is_healthy(a)  # window elapsed → attempts allowed
        assert "A" in router._unhealthy  # ...but not yet proven back
        result = await router.ainvoke("echo.who", {})
        assert result.outcome == "success"
        types = [e["event_type"] for e in store.by_correlation(f"routing-{router._host_id}")]
        assert types == ["host_marked_unhealthy"]
        # the healthy transition rode the invocation's correlation
        all_healthy = [e for c in [result.correlation.correlation_id]
                       for e in store.by_correlation(c)
                       if e["event_type"] == "host_marked_healthy"]
        assert len(all_healthy) == 1

    @pytest.mark.asyncio
    async def test_replay_merges_gateway_chain(self):
        host = make_echo_host("X", "x")
        store = self._store()
        with served(host) as url:
            router = MultiHostRouter([HttpTransport(url, name="X")], store=store)
            await router.connect()
        await router.ainvoke("echo.who", {}, correlation={"correlation_id": "corr-merge"})
        events = await router.replay("corr-merge")
        gw_events = [e for e in events if e.get("_host") == "chp-gateway"]
        assert {e["event_type"] for e in gw_events} >= {
            "host_marked_unhealthy", "execution_denied"}

    @pytest.mark.asyncio
    async def test_storeless_router_still_denies(self):
        # The returned-denial floor: no store, same outcome, just no evidence.
        router = await _router(LocalTransport(make_math_host(), name="m"))
        result = await router.ainvoke("nope.missing", {})
        assert result.denial.code == "capability_not_found"
        assert result.evidence_ids == []


# ---------------------------------------------------------------------------
# Mandate passthrough (spec §10 Forwarding, proposal 0004)
# ---------------------------------------------------------------------------

class TestMandateForwarding:
    def _mandate(self, tmp_path, scope):
        from datetime import datetime, timedelta, timezone
        from chp_core import signing
        key = signing.generate_keypair(tmp_path / "pub")
        now = datetime.now(timezone.utc)
        iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        return signing.build_mandate(
            "principal-gw-test", key, delegate_id="steward-x", scope=scope,
            valid_from=iso(now - timedelta(minutes=1)),
            valid_until=iso(now + timedelta(hours=1)), created_at=iso(now))

    @pytest.mark.asyncio
    async def test_mandate_transits_router_to_member_evidence(self, tmp_path):
        # Presented at the ROUTER, verified at the MEMBER: the executing host's
        # gate 5 rebinds the subject even though the transport subject (router)
        # was substituted at the hop — authority survives, asserted identity dies.
        member = make_echo_host("A", "a")
        router = await _router(LocalTransport(member, name="A"))
        mandate = self._mandate(tmp_path, ["echo.who"])
        result = await router.ainvoke(
            "echo.who", {}, mandate=mandate,
            correlation={"correlation_id": "corr-fwd"})
        assert result.outcome == "success"
        subj = member.replay("corr-fwd")[0].get("subject") or {}
        assert subj["type"] == "mandate"
        assert subj["id"] == "steward-x"
        assert subj["principal"] == "principal-gw-test"
        assert subj["verified"] is True

    @pytest.mark.asyncio
    async def test_mandate_transits_envelope_path(self, tmp_path):
        # The HTTP gateway path: /invoke → from_mapping → ainvoke_envelope.
        from chp_core import InvocationEnvelope
        member = make_echo_host("A", "a")
        router = await _router(LocalTransport(member, name="A"))
        env = InvocationEnvelope.from_mapping({
            "capability_id": "echo.who", "payload": {},
            "correlation": {"correlation_id": "corr-fwd-env"},
            "mandate": self._mandate(tmp_path, ["echo.who"]),
        })
        assert (await router.ainvoke_envelope(env)).outcome == "success"
        subj = member.replay("corr-fwd-env")[0].get("subject") or {}
        assert subj["type"] == "mandate" and subj["id"] == "steward-x"

    @pytest.mark.asyncio
    async def test_out_of_scope_mandate_denied_at_member(self, tmp_path):
        # The router forwards without judging; the MEMBER's gate decides.
        member = make_echo_host("A", "a")
        router = await _router(LocalTransport(member, name="A"))
        result = await router.ainvoke(
            "echo.who", {}, mandate=self._mandate(tmp_path, ["other.cap"]))
        assert result.outcome == "denied"
        assert result.denial.code == "policy_blocked"


# ---------------------------------------------------------------------------
# Active prober (reference feature — spec §11 defines none)
# ---------------------------------------------------------------------------

class TestProber:
    @pytest.mark.asyncio
    async def test_prober_detects_death_with_zero_invocations(self):
        import time as _time

        from chp_core.store import SQLiteEvidenceStore

        host = make_echo_host("P", "p")
        store = SQLiteEvidenceStore(":memory:")
        with served(host) as url:
            router = MultiHostRouter([HttpTransport(url, name="P")],
                                     store=store, recheck_interval=60.0)
            await router.connect()
            stop = router.start_prober(0.1)
        # member is now DOWN; no invocation is ever issued — the prober alone
        # must observe the transition and emit the §11 event.
        try:
            deadline = _time.time() + 5
            while _time.time() < deadline:
                events = store.by_correlation(f"routing-{router._host_id}")
                if any(e["event_type"] == "host_marked_unhealthy" for e in events):
                    break
                _time.sleep(0.1)
            else:
                raise AssertionError("prober never observed the dead member")
        finally:
            stop()
