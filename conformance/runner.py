#!/usr/bin/env python3
"""Minimal CHP v0.1 conformance runner."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    CapabilityDescriptor,
    InvariantDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from sample_failing_hosts import BrokenNoEvidenceHost  # noqa: E402


Check = Callable[[Any], Awaitable[None]]


@dataclass(slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def result_value(result: Any, name: str) -> Any:
    if isinstance(result, dict):
        return result.get(name)
    return getattr(result, name)


def evidence_ids(result: Any) -> list[str]:
    value = result_value(result, "evidence_ids")
    return list(value or [])


async def invoke_host(host: Any, *args: Any, **kwargs: Any) -> Any:
    if hasattr(host, "ainvoke"):
        return await host.ainvoke(*args, **kwargs)
    result = host.invoke(*args, **kwargs)
    if hasattr(result, "__await__"):
        return await result
    return result


async def build_passing_host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("conformance-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_ctx, payload):
        return {"echo": payload.get("value")}

    async def fail(_ctx, _payload):
        raise RuntimeError("expected failure")

    host.register(
        CapabilityDescriptor(
            id="conformance.echo",
            version="1.0.0",
            description="Echo a value.",
        ),
        echo,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.fail",
            version="1.0.0",
            description="Fail deterministically.",
        ),
        fail,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.guarded",
            version="1.0.0",
            description="Require payload.value.",
            invariants=[
                InvariantDescriptor(
                    id="requires_value",
                    kind="required_payload_fields",
                    enforcement="host",
                    parameters={"fields": ["value"]},
                )
            ],
        ),
        echo,
    )
    return host


async def check_declaration(host: Any) -> None:
    descriptor = host.discover()
    caps = descriptor.get("capabilities") or []
    assert descriptor["protocol_version"] == "0.1"
    assert any(cap["id"] == "conformance.echo" for cap in caps)


async def check_discovery(host: Any) -> None:
    descriptor = host.discover()
    assert descriptor["id"]
    assert isinstance(descriptor["capabilities"], list)
    for cap in descriptor["capabilities"]:
        assert cap["id"]
        assert cap["version"]
        assert "modes" in cap


async def check_invocation_envelope(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "ok"},
        correlation={"correlation_id": "conf-invoke"},
    )
    assert result_value(result, "success") is True
    assert result_value(result, "outcome") == "success"
    assert result_value(result, "data") == {"echo": "ok"}


async def check_correlation_propagation(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "corr"},
        correlation={"correlation_id": "conf-correlation"},
    )
    correlation = result_value(result, "correlation")
    if isinstance(correlation, dict):
        correlation_id = correlation["correlation_id"]
    else:
        correlation_id = correlation.correlation_id
    assert correlation_id == "conf-correlation"
    replay = host.replay("conf-correlation")
    assert replay
    assert {event["correlation"]["correlation_id"] for event in replay} == {"conf-correlation"}


async def check_success_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "evidence"},
        correlation={"correlation_id": "conf-success"},
    )
    assert len(evidence_ids(result)) >= 2
    event_types = [event["event_type"] for event in host.replay("conf-success")]
    assert "execution_started" in event_types
    assert "execution_completed" in event_types


async def check_failure_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.fail",
        {},
        correlation={"correlation_id": "conf-failure"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "failure"
    event_types = [event["event_type"] for event in host.replay("conf-failure")]
    assert "execution_started" in event_types
    assert "execution_failed" in event_types


async def check_denial_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.guarded",
        {},
        correlation={"correlation_id": "conf-denial"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "denied"
    event_types = [event["event_type"] for event in host.replay("conf-denial")]
    assert event_types == ["execution_denied"]


async def check_replay_by_correlation(host: Any) -> None:
    await invoke_host(
        host,
        "conformance.echo",
        {"value": "replay"},
        correlation={"correlation_id": "conf-replay"},
    )
    replay = host.replay("conf-replay")
    assert len(replay) >= 2
    sequences = [event["sequence"] for event in replay]
    assert sequences == sorted(sequences)


async def check_pretool_governance(_host: Any) -> None:
    """Pre-tool governance emits evidence and honours block policies."""
    import os
    import tempfile

    from chp_core.hooks import process_pre_tool_use
    from chp_core.policy import BlockPattern, PolicyConfig
    from chp_core.store import SQLiteEvidenceStore

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "conf-pretool-001",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "cwd": "/tmp",
        }
        result = process_pre_tool_use(payload, store_path, policy=None)
        assert not result.should_block, "expected pass without policy"

        policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
        result2 = process_pre_tool_use(payload, store_path, policy=policy)
        assert result2.should_block, "expected block with policy"

        store = SQLiteEvidenceStore(store_path)
        events = store.by_correlation("conf-pretool-001")
        store.close()
        assert len(events) == 2, f"expected 2 events, got {len(events)}"
        types = [e["event_type"] for e in events]
        assert types.count("tool_use_requested") == 2, f"missing events: {types}"
    finally:
        os.unlink(store_path)


async def check_retrieval_capability(_host: Any) -> None:
    """retrieval.query emits retrieval_started + retrieval_completed with source_refs."""
    import os
    import tempfile

    from chp_core import (
        InMemoryKeywordRetrievalCapability,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_retrieval_capability,
    )

    docs = [
        {"source_id": "doc-1", "content": "the quick brown fox", "title": "Doc 1"},
        {"source_id": "doc-2", "content": "lazy dog sleeps deeply", "title": "Doc 2"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-retrieval", store=store)
        cap = InMemoryKeywordRetrievalCapability(docs)
        register_retrieval_capability(host, cap)

        result = await host.ainvoke(
            "retrieval.query",
            {"query": "quick fox", "top_k": 2},
            correlation={"correlation_id": "conf-retrieval-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay("conf-retrieval-001")
        types = [e["event_type"] for e in events]
        assert "retrieval_started" in types, f"missing retrieval_started: {types}"
        assert "retrieval_completed" in types, f"missing retrieval_completed: {types}"

        completed = next(e for e in events if e["event_type"] == "retrieval_completed")
        assert "source_refs" in (completed.get("payload") or {}), "missing source_refs in payload"
        store.close()
    finally:
        os.unlink(store_path)


async def check_ingestion_capability(_host: Any) -> None:
    """ingestion.ingest emits ingestion_started + ingestion_completed with content_hash."""
    import os
    import tempfile

    from chp_core import (
        InMemoryTextIngestionCapability,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_ingestion_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-ingestion", store=store)
        cap = InMemoryTextIngestionCapability()
        register_ingestion_capability(host, cap)

        result = await host.ainvoke(
            "ingestion.ingest",
            {"content": "the quick brown fox", "title": "Test Doc"},
            correlation={"correlation_id": "conf-ingestion-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay("conf-ingestion-001")
        types = [e["event_type"] for e in events]
        assert "ingestion_started" in types, f"missing ingestion_started: {types}"
        assert "ingestion_completed" in types, f"missing ingestion_completed: {types}"

        completed = next(e for e in events if e["event_type"] == "ingestion_completed")
        payload = completed.get("payload") or {}
        assert "records" in payload, "missing records in payload"
        assert payload["records"][0]["content_hash"].startswith("sha256:"), "bad content_hash"
        store.close()
    finally:
        os.unlink(store_path)


async def check_transformation_capability(_host: Any) -> None:
    """transformation.transform emits transformation_started + transformation_completed with hashes."""
    import os
    import tempfile

    from chp_core import (
        InMemoryTextTransformationCapability,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_transformation_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-transformation", store=store)
        cap = InMemoryTextTransformationCapability()
        register_transformation_capability(host, cap)

        result = await host.ainvoke(
            "transformation.transform",
            {"content": "  Hello WORLD  ", "transform_type": "normalize"},
            correlation={"correlation_id": "conf-transformation-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay("conf-transformation-001")
        types = [e["event_type"] for e in events]
        assert "transformation_started" in types, f"missing transformation_started: {types}"
        assert "transformation_completed" in types, f"missing transformation_completed: {types}"

        completed = next(e for e in events if e["event_type"] == "transformation_completed")
        payload = completed.get("payload") or {}
        assert payload.get("input_hash", "").startswith("sha256:"), "bad input_hash"
        assert payload.get("output_hash", "").startswith("sha256:"), "bad output_hash"
        store.close()
    finally:
        os.unlink(store_path)


async def check_knowledge_graph_capability(_host: Any) -> None:
    """graph.* operations emit graph_entity_added, graph_relation_added, graph_queried, graph_traversed."""
    import os
    import tempfile

    from chp_core import (
        InMemoryKnowledgeGraph,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_knowledge_graph_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-graph", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)

        r1 = await host.ainvoke(
            "graph.add_entity",
            {"entity_id": "p1", "entity_type": "person", "label": "Alice"},
            correlation={"correlation_id": "conf-graph-001"},
        )
        assert r1.success, f"add_entity failed: {r1}"

        r2 = await host.ainvoke(
            "graph.add_entity",
            {"entity_id": "p2", "entity_type": "person", "label": "Bob"},
            correlation={"correlation_id": "conf-graph-001"},
        )
        assert r2.success, f"add_entity 2 failed: {r2}"

        r3 = await host.ainvoke(
            "graph.add_relation",
            {"from_entity_id": "p1", "to_entity_id": "p2", "relation_type": "knows"},
            correlation={"correlation_id": "conf-graph-001"},
        )
        assert r3.success, f"add_relation failed: {r3}"

        r4 = await host.ainvoke(
            "graph.query_entities",
            {"entity_type": "person"},
            correlation={"correlation_id": "conf-graph-001"},
        )
        assert r4.success, f"query_entities failed: {r4}"

        r5 = await host.ainvoke(
            "graph.traverse",
            {"start_id": "p1", "depth": 1},
            correlation={"correlation_id": "conf-graph-001"},
        )
        assert r5.success, f"traverse failed: {r5}"

        events = host.replay("conf-graph-001")
        types = {e["event_type"] for e in events}
        assert "graph_entity_added" in types, f"missing graph_entity_added: {types}"
        assert "graph_relation_added" in types, f"missing graph_relation_added: {types}"
        assert "graph_queried" in types, f"missing graph_queried: {types}"
        assert "graph_traversed" in types, f"missing graph_traversed: {types}"

        entity_added = next(e for e in events if e["event_type"] == "graph_entity_added")
        payload = entity_added.get("payload") or {}
        assert "entity_id" in payload, f"graph_entity_added missing entity_id: {payload}"
        assert "entity_type" in payload, f"graph_entity_added missing entity_type: {payload}"

        queried = next(e for e in events if e["event_type"] == "graph_queried")
        q_payload = queried.get("payload") or {}
        assert "entity_count" in q_payload, f"graph_queried missing entity_count: {q_payload}"
        assert "entities" not in q_payload, f"graph_queried must not include entities: {q_payload}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_workflow_capability(_host: Any) -> None:
    """workflow.run executes steps sequentially and emits workflow_started, step, and workflow_completed events."""
    import os
    import tempfile

    from chp_core import (
        InMemoryKnowledgeGraph,
        InMemoryWorkflow,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_knowledge_graph_capability,
        register_workflow_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-workflow", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)

        result = await host.ainvoke(
            "workflow.run",
            {
                "workflow_id": "conf-wf-001",
                "name": "conformance-workflow",
                "steps": [
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "e1", "entity_type": "node"}},
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "e2", "entity_type": "node"}},
                ],
            },
            correlation={"correlation_id": "conf-workflow-001"},
        )
        assert result.success, f"workflow.run failed: {result}"

        events = host.replay("conf-workflow-001")
        types = [e["event_type"] for e in events]
        assert "workflow_started" in types, f"missing workflow_started: {types}"
        assert "workflow_completed" in types, f"missing workflow_completed: {types}"
        assert types.count("workflow_step_started") >= 2, f"missing workflow_step_started x2: {types}"
        assert types.count("workflow_step_completed") >= 2, f"missing workflow_step_completed x2: {types}"

        completed = next(e for e in events if e["event_type"] == "workflow_completed")
        payload = completed.get("payload") or {}
        assert payload.get("completed_steps") == 2, f"expected completed_steps=2: {payload}"
        assert payload.get("failed_steps") == 0, f"expected failed_steps=0: {payload}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_event_bus_capability(_host: Any) -> None:
    """events.emit records domain_event_emitted with data_hash (no raw data); events.query returns count."""
    import os
    import tempfile

    from chp_core import (
        InMemoryEventBus,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_event_bus_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-events", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)

        r1 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {"order_id": "o1"}},
            correlation={"correlation_id": "conf-events-001"},
        )
        assert r1.success, f"events.emit 1 failed: {r1}"

        r2 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {"order_id": "o2"}},
            correlation={"correlation_id": "conf-events-001"},
        )
        assert r2.success, f"events.emit 2 failed: {r2}"

        r3 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.shipped", "source": "fulfillment", "data": {}},
            correlation={"correlation_id": "conf-events-001"},
        )
        assert r3.success, f"events.emit 3 failed: {r3}"

        r4 = await host.ainvoke(
            "events.query",
            {"event_type": "order.placed"},
            correlation={"correlation_id": "conf-events-001"},
        )
        assert r4.success, f"events.query failed: {r4}"

        events = host.replay("conf-events-001")
        types = [e["event_type"] for e in events]
        assert types.count("domain_event_emitted") == 3, f"expected 3 domain_event_emitted: {types}"
        assert "domain_events_queried" in types, f"missing domain_events_queried: {types}"

        emitted = next(e for e in events if e["event_type"] == "domain_event_emitted")
        em_payload = emitted.get("payload") or {}
        assert em_payload.get("data_hash", "").startswith("sha256:"), f"bad data_hash: {em_payload}"
        assert "data" not in em_payload, f"evidence must not include raw data: {em_payload}"

        store.close()
    finally:
        os.unlink(store_path)


CHECKS: list[tuple[str, Check]] = [
    ("capability declaration", check_declaration),
    ("capability discovery", check_discovery),
    ("invocation through envelope", check_invocation_envelope),
    ("correlation propagation", check_correlation_propagation),
    ("evidence emission on success", check_success_evidence),
    ("evidence emission on failure", check_failure_evidence),
    ("evidence emission on denial", check_denial_evidence),
    ("replay by correlation id", check_replay_by_correlation),
    ("pre-tool governance", check_pretool_governance),
    ("retrieval capability", check_retrieval_capability),
    ("ingestion capability", check_ingestion_capability),
    ("transformation capability", check_transformation_capability),
    ("knowledge graph capability", check_knowledge_graph_capability),
    ("workflow capability", check_workflow_capability),
    ("event bus capability", check_event_bus_capability),
]


async def run(sample: str) -> list[CheckResult]:
    if sample == "passing":
        host = await build_passing_host()
    elif sample == "failing-no-evidence":
        host = BrokenNoEvidenceHost()
    else:
        raise ValueError(f"unknown sample host: {sample}")

    results = []
    for name, check in CHECKS:
        try:
            await check(host)
            results.append(CheckResult(name, True))
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(name, False, str(exc) or exc.__class__.__name__))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CHP v0.1 conformance checks.")
    parser.add_argument(
        "--sample",
        choices=["passing", "failing-no-evidence"],
        default="passing",
        help="Built-in sample host to test.",
    )
    args = parser.parse_args()

    results = asyncio.run(run(args.sample))
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        suffix = f" - {result.detail}" if result.detail else ""
        print(f"{status} {result.name}{suffix}")

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
