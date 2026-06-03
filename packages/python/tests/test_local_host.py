from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDescriptor,
    CorrelationContext,
    InvariantDescriptor,
    LocalCapabilityHost,
    ReplayQuery,
    SQLiteEvidenceStore,
    capability,
    evidence_to_otel_span,
    replay_to_otel_spans,
    record_codex_action,
    redact_payload,
    register_builtin_capabilities,
)


class LocalHostTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("test-host", store=SQLiteEvidenceStore(":memory:"))

    async def test_discovery_and_success_evidence(self) -> None:
        async def handler(_ctx, payload):
            return {"sum": payload["a"] + payload["b"]}

        self.host.register(
            CapabilityDescriptor(
                id="math.add",
                version="1.0.0",
                description="Add two numbers.",
            ),
            handler,
        )

        discovered = self.host.discover()
        self.assertEqual(discovered["id"], "test-host")
        self.assertEqual(discovered["capabilities"][0]["id"], "math.add")

        correlation = CorrelationContext(correlation_id="corr-fixed")
        result = await self.host.ainvoke(
            "math.add",
            {"a": 2, "b": 3},
            correlation=correlation,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.data, {"sum": 5})
        self.assertEqual(result.correlation.correlation_id, "corr-fixed")

        replay = self.host.replay("corr-fixed")
        self.assertEqual([event["event_type"] for event in replay], ["execution_started", "execution_completed"])
        self.assertEqual({event["host_id"] for event in replay}, {"test-host"})

        replay_result = self.host.replay_result(ReplayQuery(correlation_id="corr-fixed"))
        self.assertEqual(replay_result.event_count, 2)
        self.assertEqual(replay_result.events, replay)
        self.assertEqual([event["sequence"] for event in replay], [1, 2])
        self.assertEqual(replay[0]["sequence"], replay[0]["sequence"])

    async def test_failure_evidence(self) -> None:
        async def handler(_ctx, _payload):
            raise RuntimeError("boom")

        self.host.register(
            CapabilityDescriptor(
                id="failure.example",
                version="1.0.0",
                description="Fail.",
            ),
            handler,
        )

        result = await self.host.ainvoke(
            "failure.example",
            {},
            correlation={"correlation_id": "corr-fail"},
        )

        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "failure")
        replay = self.host.replay("corr-fail")
        self.assertEqual(replay[-1]["event_type"], "execution_failed")
        self.assertEqual(replay[-1]["error"]["type"], "RuntimeError")

    async def test_denial_evidence_for_missing_capability(self) -> None:
        result = await self.host.ainvoke(
            "missing.capability",
            {},
            correlation={"correlation_id": "corr-denied"},
        )

        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "denied")
        replay = self.host.replay("corr-denied")
        self.assertEqual(len(replay), 1)
        self.assertEqual(replay[0]["event_type"], "execution_denied")
        self.assertEqual(replay[0]["denial"]["code"], "capability_not_found")

    async def test_host_invariant_denies_before_execution(self) -> None:
        async def handler(_ctx, _payload):
            return {"should_not_run": True}

        self.host.register(
            CapabilityDescriptor(
                id="guarded.example",
                version="1.0.0",
                description="Requires a payload field.",
                invariants=[
                    InvariantDescriptor(
                        id="requires_target",
                        kind="required_payload_fields",
                        enforcement="host",
                        parameters={"fields": ["target"]},
                    )
                ],
            ),
            handler,
        )

        result = await self.host.ainvoke(
            "guarded.example",
            {},
            correlation={"correlation_id": "corr-invariant"},
        )

        self.assertFalse(result.success)
        self.assertEqual(result.denial.code, "invariant_failed")
        replay = self.host.replay("corr-invariant")
        self.assertEqual([event["event_type"] for event in replay], ["execution_denied"])

    async def test_disabled_capability_can_be_skipped(self) -> None:
        async def handler(_ctx, _payload):
            return {"should_not_run": True}

        self.host.register(
            CapabilityDescriptor(
                id="disabled.example",
                version="1.0.0",
                description="Disabled capability.",
            ),
            handler,
            enabled=False,
        )

        result = await self.host.ainvoke(
            "disabled.example",
            {},
            correlation={"correlation_id": "corr-skipped"},
        )

        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "skipped")
        replay = self.host.replay("corr-skipped")
        self.assertEqual([event["event_type"] for event in replay], ["execution_skipped"])

    def test_decorator_registration_and_sync_invoke(self) -> None:
        @capability(
            id="example.search_information",
            version="0.1.0",
            description="Search for information.",
        )
        def search_information(query: str):
            return {"query": query, "matches": ["CHP wraps execution evidence"]}

        self.host.register(search_information)

        result = self.host.invoke(
            capability_id="example.search_information",
            payload={"query": "CHP vs MCP"},
            correlation_id="corr-sync",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.data["query"], "CHP vs MCP")
        self.assertEqual(len(self.host.replay("corr-sync")), 2)

    async def test_evidence_payload_redaction(self) -> None:
        async def handler(ctx, _payload):
            ctx.emit(
                "custom_payload",
                {
                    "api_key": "secret-key",
                    "nested": {"access_token": "secret-token"},
                    "safe": "visible",
                },
            )
            return {"ok": True}

        self.host.register(
            CapabilityDescriptor(
                id="redaction.example",
                version="1.0.0",
                description="Emit sensitive payload.",
            ),
            handler,
        )

        await self.host.ainvoke(
            "redaction.example",
            {},
            correlation={"correlation_id": "corr-redaction"},
        )

        custom = self.host.replay("corr-redaction")[1]
        self.assertEqual(custom["payload"]["api_key"], "[REDACTED]")
        self.assertEqual(custom["payload"]["nested"]["access_token"], "[REDACTED]")
        self.assertEqual(custom["payload"]["safe"], "visible")
        self.assertEqual(
            redact_payload({"password": "pw", "value": "ok"}),
            {"password": "[REDACTED]", "value": "ok"},
        )

    async def test_otel_mapping_from_replay(self) -> None:
        async def handler(_ctx, payload):
            return {"sum": payload["a"] + payload["b"]}

        self.host.register(
            CapabilityDescriptor(
                id="otel.add",
                version="1.0.0",
                description="Add two numbers.",
            ),
            handler,
        )

        await self.host.ainvoke(
            "otel.add",
            {"a": 1, "b": 2},
            correlation={"correlation_id": "corr-otel"},
        )

        replay = self.host.replay("corr-otel")
        single = evidence_to_otel_span(replay[-1])
        self.assertEqual(single["attributes"]["chp.capability_id"], "otel.add")
        self.assertEqual(single["status"], {"code": "OK"})

        spans = replay_to_otel_spans(replay)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0]["name"], "otel.add")
        self.assertEqual([event["name"] for event in spans[0]["events"]], ["execution_started", "execution_completed"])

    def test_codex_self_observation_records_engineering_action(self) -> None:
        result = record_codex_action(
            self.host,
            "codex.run_tests",
            {
                "task_intent": "Verify CHP v0.1 local host.",
                "files_inspected": ["packages/python/chp_core/host.py"],
                "files_changed": ["packages/python/tests/test_local_host.py"],
                "commands_run": ["python -m unittest discover -s packages/python/tests"],
                "tests_run": ["unit"],
                "outcome": "success",
                "open_questions": [],
                "follow_up_actions": ["Run conformance."],
            },
            correlation_id="corr-codex",
        )

        self.assertTrue(result.success)
        replay = self.host.replay("corr-codex")
        self.assertEqual(
            [event["event_type"] for event in replay],
            ["execution_started", "codex_action_recorded", "execution_completed"],
        )
        self.assertEqual(replay[1]["payload"]["task_intent"], "Verify CHP v0.1 local host.")

    async def test_builtin_capabilities(self) -> None:
        register_builtin_capabilities(self.host)

        trace = await self.host.ainvoke(
            "trace_execution",
            {
                "source_id": "agent.local",
                "event_type": "tool_call",
                "summary": "Agent called a local tool.",
            },
            correlation={"correlation_id": "corr-trace"},
        )
        self.assertTrue(trace.success)
        self.assertIn("observed_event_id", trace.data)

        explanation = await self.host.ainvoke(
            "explain_execution",
            {"correlation_id": "corr-trace"},
        )
        self.assertTrue(explanation.success)
        self.assertGreaterEqual(len(explanation.data["facts"]), 3)
        self.assertGreaterEqual(len(explanation.data["inferences"]), 1)

        counterfactual = await self.host.ainvoke(
            "evaluate_counterfactual",
            {
                "correlation_id": "corr-trace",
                "invariant": {
                    "id": "deny_tool_calls",
                    "kind": "deny_external_event_type",
                    "parameters": {"event_type": "tool_call"},
                },
            },
        )
        self.assertTrue(counterfactual.success)
        self.assertTrue(counterfactual.data["would_have_denied"])
        self.assertFalse(counterfactual.data["would_have_warned"])
        self.assertTrue(counterfactual.data["would_deny"])
        self.assertEqual(len(counterfactual.data["violating_events"]), 1)


    async def test_query_evidence_by_outcome(self) -> None:
        async def success_handler(_ctx, _payload):
            return {"ok": True}

        async def fail_handler(_ctx, _payload):
            raise RuntimeError("expected failure")

        self.host.register(CapabilityDescriptor(id="q.success", version="1.0.0", description=""), success_handler)
        self.host.register(CapabilityDescriptor(id="q.fail", version="1.0.0", description=""), fail_handler)

        await self.host.ainvoke("q.success", {}, correlation={"correlation_id": "corr-q1"})
        await self.host.ainvoke("q.fail", {}, correlation={"correlation_id": "corr-q2"})

        successes = self.host.query_evidence(outcome="success")
        failures = self.host.query_evidence(outcome="failure")

        self.assertTrue(all(e["outcome"] == "success" for e in successes))
        self.assertTrue(all(e["outcome"] == "failure" for e in failures))
        self.assertGreaterEqual(len(successes), 1)
        self.assertGreaterEqual(len(failures), 1)

    async def test_query_evidence_by_capability(self) -> None:
        async def handler_a(_ctx, _payload):
            return {"source": "a"}

        async def handler_b(_ctx, _payload):
            return {"source": "b"}

        self.host.register(CapabilityDescriptor(id="cap.a", version="1.0.0", description=""), handler_a)
        self.host.register(CapabilityDescriptor(id="cap.b", version="1.0.0", description=""), handler_b)

        await self.host.ainvoke("cap.a", {}, correlation={"correlation_id": "corr-qa"})
        await self.host.ainvoke("cap.b", {}, correlation={"correlation_id": "corr-qb"})

        events_a = self.host.query_evidence(capability_id="cap.a")
        events_b = self.host.query_evidence(capability_id="cap.b")

        self.assertTrue(all(e["capability_id"] == "cap.a" for e in events_a))
        self.assertTrue(all(e["capability_id"] == "cap.b" for e in events_b))
        self.assertEqual(len(events_a), 2)
        self.assertEqual(len(events_b), 2)

    async def test_evidence_count(self) -> None:
        async def handler(_ctx, _payload):
            return {}

        self.host.register(CapabilityDescriptor(id="count.cap", version="1.0.0", description=""), handler)

        corr = "corr-count"
        for _ in range(3):
            await self.host.ainvoke("count.cap", {}, correlation={"correlation_id": corr})

        self.assertEqual(self.host.evidence_count(corr), 6)

    async def test_invoke_in_async_context_raises(self) -> None:
        async def handler(_ctx, _payload):
            return {}

        self.host.register(CapabilityDescriptor(id="async.check", version="1.0.0", description=""), handler)

        with self.assertRaises(RuntimeError) as cm:
            self.host.invoke("async.check", {})

        self.assertIn("ainvoke", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
