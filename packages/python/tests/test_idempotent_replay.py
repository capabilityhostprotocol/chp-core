"""Idempotent invocation replay (chp-v0.2.md §13, proposal 0008): gate 0
replays recorded results, denials replay as-is, the cache is window-bounded
serving state, and purge cascades."""

from __future__ import annotations

import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core.policy import PolicyConfig
from chp_core.types import CorrelationContext


def _host(policy=None) -> LocalCapabilityHost:
    host = LocalCapabilityHost("replay-host",
                               store=SQLiteEvidenceStore(":memory:"), policy=policy)
    calls = {"n": 0}

    async def counting(_ctx, payload):
        calls["n"] += 1
        return {"echo": payload.get("value"), "execution": calls["n"]}

    host.register(
        CapabilityDescriptor(id="replay.echo", version="1.0.0", description="."),
        counting)
    host.register(
        CapabilityDescriptor(id="replay.risky", version="1.0.0", description=".",
                             risk="high"),
        counting)
    host._test_calls = calls  # type: ignore[attr-defined]
    return host


class ReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_replays_without_reexecution(self) -> None:
        host = _host()
        env = {"capability_id": "replay.echo", "payload": {"value": "hi"},
               "invocation_id": "inv_replay_test_1",
               "correlation": {"correlation_id": "replay-corr-1"}}
        first = await host.ainvoke_envelope(dict(env))
        second = await host.ainvoke_envelope(dict(env))

        self.assertEqual(first.outcome, "success")
        self.assertEqual(second.outcome, "success")
        self.assertEqual(first.data, second.data)  # the RECORDED result, verbatim
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(host._test_calls["n"], 1)  # executed ONCE
        events = host.replay("replay-corr-1")
        self.assertEqual(
            sum(1 for e in events if e["event_type"] == "execution_started"), 1)

    async def test_fresh_id_executes_fresh(self) -> None:
        host = _host()
        r1 = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="replay.echo", payload={"value": "x"}))
        r2 = await host.ainvoke_envelope(InvocationEnvelope(
            capability_id="replay.echo", payload={"value": "x"}))
        self.assertNotEqual(r1.data["execution"], r2.data["execution"])
        self.assertEqual(host._test_calls["n"], 2)

    async def test_denial_replays_as_same_denial(self) -> None:
        host = _host(policy=PolicyConfig(max_risk_tier="medium"))
        env = {"capability_id": "replay.risky", "payload": {},
               "invocation_id": "inv_replay_denied_1",
               "correlation": {"correlation_id": "replay-corr-denied"}}
        first = await host.ainvoke_envelope(dict(env))
        second = await host.ainvoke_envelope(dict(env))
        self.assertEqual(first.outcome, "denied")
        self.assertEqual(second.outcome, "denied")
        self.assertEqual(second.denial.code, first.denial.code)
        self.assertTrue(second.replayed)
        events = host.replay("replay-corr-denied")
        self.assertEqual(
            sum(1 for e in events if e["event_type"] == "execution_denied"), 1)

    async def test_ttl_zero_disables_replay(self) -> None:
        host = _host()
        env = {"capability_id": "replay.echo", "payload": {"value": "y"},
               "invocation_id": "inv_replay_ttl_0"}
        with unittest.mock.patch.dict("os.environ", {"CHP_RESULT_CACHE_TTL_S": "0"}):
            await host.ainvoke_envelope(dict(env))
            second = await host.ainvoke_envelope(dict(env))
        self.assertFalse(second.replayed)
        self.assertEqual(host._test_calls["n"], 2)

    async def test_stream_mode_excluded(self) -> None:
        host = _host()

        async def streaming(_ctx, _payload):
            yield "c1"
            from chp_core.types import StreamResult
            yield StreamResult({"done": True})

        host.register(
            CapabilityDescriptor(id="replay.stream", version="1.0.0",
                                 description=".", modes=["sync", "stream"]),
            streaming)
        env = InvocationEnvelope(capability_id="replay.stream", payload={},
                                 mode="stream", invocation_id="inv_stream_dup")
        items1 = [i async for i in host.ainvoke_stream(env)]
        env2 = InvocationEnvelope(capability_id="replay.stream", payload={},
                                  mode="stream", invocation_id="inv_stream_dup")
        items2 = [i async for i in host.ainvoke_stream(env2)]
        # Streams never replay: both runs streamed chunks + a fresh result.
        self.assertTrue(any("chunk" in i for i in items1))
        self.assertTrue(any("chunk" in i for i in items2))
        result2 = [i for i in items2 if "result" in i][0]["result"]
        self.assertFalse(result2.replayed)


class ReplayCacheTests(unittest.TestCase):
    def test_purge_cascade_drops_cached_results(self) -> None:
        import asyncio

        from chp_core.compliance import SQLiteComplianceManager

        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost("cascade-host", store=store)

        async def handler(_ctx, payload):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="c.cap", version="1.0.0",
                                           description="."), handler)
        asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="c.cap", payload={}, invocation_id="inv_cascade_1",
            correlation=CorrelationContext(correlation_id="cascade-corr"))))
        self.assertIsNotNone(store.lookup_result("inv_cascade_1"))

        purged = SQLiteComplianceManager(store).purge("*", "9999-01-01T00:00:00Z")
        self.assertGreater(purged, 0)
        self.assertIsNone(store.lookup_result("inv_cascade_1"))

    def test_to_dict_omits_replayed_when_false(self) -> None:
        from chp_core.types import InvocationResult

        r = InvocationResult(
            invocation_id="inv_x", capability_id="c", capability_version="1",
            correlation=CorrelationContext(correlation_id="k"),
            outcome="success", success=True)
        self.assertNotIn("replayed", r.to_dict())
        r.replayed = True
        self.assertTrue(r.to_dict()["replayed"])

    def test_first_recorded_result_wins(self) -> None:
        store = SQLiteEvidenceStore(":memory:")
        store.record_result("inv_dup", {"marker": "first"})
        store.record_result("inv_dup", {"marker": "second"})
        self.assertEqual(store.lookup_result("inv_dup")["marker"], "first")


if __name__ == "__main__":
    unittest.main()


class ClientRetryStableIdTests(unittest.TestCase):
    def test_retry_attempts_reuse_one_invocation_id(self) -> None:
        from chp_core.http import RemoteCapabilityHost

        remote = RemoteCapabilityHost("http://127.0.0.1:1", retries=2)
        bodies: list[dict] = []

        def fake_post(path, body):
            bodies.append(dict(body))
            if len(bodies) == 1:
                raise ConnectionError("dropped mid-flight")
            return {"invocation_id": body["invocation_id"], "capability_id": "x",
                    "capability_version": None, "outcome": "success",
                    "success": True, "correlation": {"correlation_id": "c"},
                    "evidence_ids": []}

        remote._post = fake_post  # type: ignore[method-assign]
        result = remote.invoke("x", {})
        self.assertEqual(result.outcome, "success")
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0]["invocation_id"], bodies[1]["invocation_id"])
