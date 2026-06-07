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


async def check_metrics_report(_host: Any) -> None:
    """aggregate_session_metrics counts host-level invocations; format_prometheus emits chp_invocations_*."""
    import os
    import tempfile

    from chp_core import (
        InMemoryKeywordRetrievalCapability,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        aggregate_session_metrics,
        format_prometheus,
        register_retrieval_capability,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-metrics", store=store)
        cap = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, cap)

        corr = "conf-metrics-001"
        for _ in range(3):
            await host.ainvoke("retrieval.query", {"query": "test"}, correlation={"correlation_id": corr})

        events = store.by_correlation(corr)
        store.close()

        report = aggregate_session_metrics(corr, events)
        assert report.total_invocations == 3, f"expected 3 invocations, got {report.total_invocations}"
        assert "retrieval.query" in report.capabilities, f"missing retrieval.query in {list(report.capabilities)}"
        assert report.capabilities["retrieval.query"].invocations == 3

        prom = format_prometheus(report)
        assert "chp_invocations_total" in prom, "missing chp_invocations_total in Prometheus output"
        assert 'capability_id="retrieval.query"' in prom
    finally:
        os.unlink(store_path)


async def check_certification(_host: Any) -> None:
    """assess_maturity returns MaturityAssessment; CertificationRecord serialises correctly."""
    from chp_core import CertificationRecord, assess_maturity
    from chp_core.types import CapabilityCategory, CapabilityDescriptor

    descriptor = CapabilityDescriptor(
        id="conf.cap",
        version="1.0.0",
        description="Conformance test capability",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        tags=["conformance"],
        emits=["execution_started", "execution_completed", "execution_failed", "execution_denied"],
    )
    events = [
        {"event_type": "execution_started", "payload": {}},
        {"event_type": "execution_completed", "payload": {}},
    ]

    assessment = assess_maturity("conf.cap", descriptor=descriptor, events=events)
    assert assessment.level >= 2, f"expected level >= 2, got {assessment.level}"
    assert len(assessment.criteria) == 7, f"expected 7 criteria, got {len(assessment.criteria)}"
    for c in assessment.criteria:
        assert isinstance(c.passed, bool), f"criterion passed must be bool, got {type(c.passed)}"

    record = CertificationRecord(
        capability_id="conf.cap",
        level=2,
        granted_by="conformance-runner",
        certified_at="2026-01-01T00:00:00Z",
    )
    d = record.to_dict()
    assert d["capability_id"] == "conf.cap"
    assert d["level"] == 2
    assert d["granted_by"] == "conformance-runner"
    assert "certified_at" in d


async def check_version_control_capability(_host: Any) -> None:
    """chp.version_control.inspect_repo emits version_control_repo_inspected with repo metadata."""
    import os
    import tempfile

    from chp_core import (
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_git_capabilities,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-vc", store=store)
        register_git_capabilities(host)

        repo_root = str(REPO_ROOT)
        result = await host.ainvoke(
            "chp.version_control.inspect_repo",
            {"repo_root": repo_root},
            correlation={"correlation_id": "conf-vc-001"},
        )
        assert result.success, f"inspect_repo failed: {result}"

        events = host.replay("conf-vc-001")
        types = {e["event_type"] for e in events}
        assert "version_control_repo_inspected" in types, f"missing version_control_repo_inspected: {types}"

        inspected = next(e for e in events if e["event_type"] == "version_control_repo_inspected")
        payload = inspected.get("payload") or {}
        assert "branch" in payload or "repo_root" in payload, f"missing repo metadata in payload: {payload}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_identity_propagation(_host: Any) -> None:
    """subject from ainvoke() propagates onto all ExecutionEvidence events."""
    import os
    import tempfile

    from chp_core import (
        CapabilityDescriptor,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-identity", store=store)

        async def _echo(ctx, payload):
            return {"ok": True}

        host.register(
            CapabilityDescriptor(id="identity.echo", version="1.0.0", description="Echo"),
            _echo,
        )

        subject = {"id": "conf-agent", "type": "agent"}
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": "conf-identity-001"},
            subject=subject,
        )

        events = host.replay("conf-identity-001")
        exec_events = [e for e in events if "execution" in e["event_type"]]
        assert exec_events, "no execution events emitted"
        for ev in exec_events:
            assert ev.get("subject") == subject, (
                f"subject mismatch on {ev['event_type']}: expected {subject}, got {ev.get('subject')}"
            )
        store.close()
    finally:
        os.unlink(store_path)


async def check_composability_declaration(_host: Any) -> None:
    """depends_on on CapabilityDescriptor appears in discover() and is omitted when None."""
    import os
    import tempfile

    from chp_core import (
        CapabilityDescriptor,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-compose", store=store)

        async def _noop(ctx, payload):
            return {}

        host.register(
            CapabilityDescriptor(id="comp.a", version="1.0.0", description="A"),
            _noop,
        )
        host.register(
            CapabilityDescriptor(
                id="comp.b", version="1.0.0", description="B",
                depends_on=["comp.a"],
            ),
            _noop,
        )
        store.close()

        descriptor = host.discover()
        caps = {c["id"]: c for c in descriptor["capabilities"]}

        assert "depends_on" not in caps["comp.a"], "comp.a must not have depends_on"
        assert "depends_on" in caps["comp.b"], "comp.b must have depends_on"
        assert caps["comp.b"]["depends_on"] == ["comp.a"]
    finally:
        os.unlink(store_path)


async def check_state_machine_capability(_host: Any) -> None:
    """state_machine.* capabilities create, transition, and query machine instances with evidence."""
    import os
    import tempfile

    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.state_machine import InMemoryStateMachine, register_state_machine_capability

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-sm", store=store)
        register_state_machine_capability(host, InMemoryStateMachine())

        corr = "conf-sm-001"
        r_create = await host.ainvoke(
            "state_machine.create",
            {
                "name": "release-gate",
                "definition": {
                    "states": ["pending", "approved", "rejected"],
                    "transitions": {"pending": ["approved", "rejected"]},
                    "initial_state": "pending",
                    "terminal_states": ["approved", "rejected"],
                },
                "context": {"version": "0.5.0"},
            },
            correlation={"correlation_id": corr},
        )
        assert r_create.success, f"state_machine.create failed: {r_create}"
        machine_id = r_create.data["machine_id"]
        assert r_create.data["current_state"] == "pending"

        r_transition = await host.ainvoke(
            "state_machine.transition",
            {"machine_id": machine_id, "event": "approved"},
            correlation={"correlation_id": corr},
        )
        assert r_transition.success, f"state_machine.transition failed: {r_transition}"
        assert r_transition.data["allowed"] is True
        assert r_transition.data["to_state"] == "approved"

        r_get = await host.ainvoke(
            "state_machine.get",
            {"machine_id": machine_id},
            correlation={"correlation_id": corr},
        )
        assert r_get.success, f"state_machine.get failed: {r_get}"
        assert r_get.data["current_state"] == "approved"
        assert r_get.data["status"] == "done"

        events = host.replay(corr)
        types = {e["event_type"] for e in events}
        assert "state_machine_created" in types, f"missing state_machine_created: {types}"
        assert "state_machine_completed" in types, f"missing state_machine_completed: {types}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_agent_interface(_host: Any) -> None:
    """CostHint and SafetyHint serialize correctly; capabilities_to_tool_list emits valid tool dicts."""
    from chp_core.agent_interface import capabilities_to_tool_list, capability_to_anthropic_tool
    from chp_core.types import CapabilityDescriptor, CostHint, SafetyHint

    desc = CapabilityDescriptor(
        id="conf.action",
        version="1.0.0",
        description="Conformance action.",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        cost_hint=CostHint(token_estimate=200, latency_ms_p50=50),
        safety_hint=SafetyHint(reversible=False, destructive=True),
    )

    tool = capability_to_anthropic_tool(desc)
    assert tool["name"] == "conf_action", f"unexpected name: {tool['name']}"
    assert "irreversible" in tool["description"], "safety hint not in description"
    assert "destructive" in tool["description"], "destructive not in description"
    assert tool["input_schema"]["type"] == "object"

    d = desc.to_dict()
    assert "cost_hint" in d, "cost_hint missing from to_dict()"
    assert d["cost_hint"]["token_estimate"] == 200
    assert "safety_hint" in d, "safety_hint missing from to_dict()"

    plain = CapabilityDescriptor(id="conf.plain", version="1.0.0", description="Plain.")
    tools = capabilities_to_tool_list([plain], format="anthropic")
    assert len(tools) == 1
    assert "[" not in tools[0]["description"], "unexpected safety suffix on plain descriptor"

    openai_tools = capabilities_to_tool_list([desc], format="openai")
    assert openai_tools[0]["type"] == "function"
    assert "parameters" in openai_tools[0]["function"]


async def check_incident_capability(_host: Any) -> None:
    """incident.* capabilities open, escalate, resolve, and close incidents with evidence."""
    import os
    import tempfile

    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.incident import InMemoryIncidentManager, register_incident_capability

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-incident", store=store)
        register_incident_capability(host, InMemoryIncidentManager())

        corr = "conf-incident-001"
        r_open = await host.ainvoke(
            "incident.open",
            {"title": "DB latency spike", "severity": "P2", "correlation_ids": ["corr-001"]},
            correlation={"correlation_id": corr},
        )
        assert r_open.success, f"incident.open failed: {r_open}"
        incident_id = r_open.data["incident_id"]
        assert r_open.data["status"] == "open"
        assert r_open.data["severity"] == "P2"

        r_escalate = await host.ainvoke(
            "incident.escalate",
            {"incident_id": incident_id, "note": "paging on-call"},
            correlation={"correlation_id": corr},
        )
        assert r_escalate.success, f"incident.escalate failed: {r_escalate}"
        assert r_escalate.data["status"] == "escalated"

        r_resolve = await host.ainvoke(
            "incident.resolve",
            {"incident_id": incident_id, "note": "rolled back bad deploy"},
            correlation={"correlation_id": corr},
        )
        assert r_resolve.success, f"incident.resolve failed: {r_resolve}"
        assert r_resolve.data["status"] == "resolved"
        assert r_resolve.data["resolved_at"] is not None

        r_close = await host.ainvoke(
            "incident.close",
            {"incident_id": incident_id},
            correlation={"correlation_id": corr},
        )
        assert r_close.success, f"incident.close failed: {r_close}"
        assert r_close.data["status"] == "closed"

        r_list = await host.ainvoke(
            "incident.list",
            {"status": "closed"},
            correlation={"correlation_id": corr},
        )
        assert r_list.success, f"incident.list failed: {r_list}"
        assert r_list.data["count"] == 1

        events = host.replay(corr)
        types = {e["event_type"] for e in events}
        assert "incident_opened" in types, f"missing incident_opened: {types}"
        assert "incident_escalated" in types, f"missing incident_escalated: {types}"
        assert "incident_resolved" in types, f"missing incident_resolved: {types}"
        assert "incident_closed" in types, f"missing incident_closed: {types}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_safety_capability(_host: Any) -> None:
    """safety.assess returns structured risk assessment with evidence; high-risk caps score higher."""
    import os
    import tempfile

    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.safety import RuleBasedSafetyEvaluator, register_safety_capability

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-safety", store=store)
        register_safety_capability(host, RuleBasedSafetyEvaluator())

        corr = "conf-safety-001"
        r_low = await host.ainvoke(
            "safety.assess",
            {"capability_id": "retrieval.query", "payload": {"query": "hello"}},
            correlation={"correlation_id": corr},
        )
        assert r_low.success, f"safety.assess failed: {r_low}"
        assert "level" in r_low.data, f"missing level in {r_low.data}"
        assert r_low.data["recommendation"] in ("allow", "warn", "require_approval", "block")
        assert 0.0 <= r_low.data["score"] <= 1.0
        assert r_low.data["level"] == "low", f"expected low for retrieval: {r_low.data}"

        r_high = await host.ainvoke(
            "safety.assess",
            {"capability_id": "claude_code.bash", "payload": {"command": "echo hello"}},
            correlation={"correlation_id": corr},
        )
        assert r_high.success, f"safety.assess high failed: {r_high}"
        assert r_high.data["level"] in ("medium", "high", "critical"), (
            f"expected elevated risk for bash: {r_high.data}"
        )
        assert r_high.data["score"] > r_low.data["score"], "bash should score higher than retrieval"

        events = host.replay(corr)
        types = {e["event_type"] for e in events}
        assert "safety_assessment_started" in types, f"missing safety_assessment_started: {types}"
        assert "safety_assessment_completed" in types, f"missing safety_assessment_completed: {types}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_compliance_capability(_host: Any) -> None:
    """compliance.apply_retention purges old evidence; compliance.report emits compliance events."""
    import os
    import tempfile

    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.compliance import SQLiteComplianceManager, register_compliance_capability

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-compliance", store=store)

        async def _noop(ctx, payload):
            return {"ok": True}

        host.register(
            CapabilityDescriptor(id="test.noop", version="1.0.0", description="noop"),
            _noop,
        )
        for i in range(3):
            await host.ainvoke("test.noop", {}, correlation={"correlation_id": f"seed-{i}"})

        manager = SQLiteComplianceManager(store)
        register_compliance_capability(host, manager)

        corr = "conf-compliance-001"
        r_report = await host.ainvoke(
            "compliance.report",
            {},
            correlation={"correlation_id": corr},
        )
        assert r_report.success, f"compliance.report failed: {r_report}"
        assert r_report.data["events_inspected"] > 0, "expected events from seeding"

        r_apply = await host.ainvoke(
            "compliance.apply_retention",
            {
                "policies": [
                    {
                        "policy_id": "purge-all",
                        "retain_days": 0,
                        "applies_to": ["test.noop"],
                    }
                ]
            },
            correlation={"correlation_id": corr},
        )
        assert r_apply.success, f"compliance.apply_retention failed: {r_apply}"
        assert r_apply.data["events_purged"] > 0, f"expected purged events: {r_apply.data}"

        events = host.replay(corr)
        types = {e["event_type"] for e in events}
        assert "compliance_report_generated" in types, f"missing compliance_report_generated: {types}"
        assert "retention_policy_applied" in types, f"missing retention_policy_applied: {types}"

        store.close()
    finally:
        os.unlink(store_path)


async def check_persistence(_host: Any) -> None:
    """SQLite-backed capabilities persist state across manager reinstantiation."""
    import os
    import tempfile

    from chp_core.state_machine import SQLiteStateMachine
    from chp_core.incident import SQLiteIncidentManager

    with tempfile.TemporaryDirectory() as tmpdir:
        sm_path = os.path.join(tmpdir, "state_machines.sqlite")
        inc_path = os.path.join(tmpdir, "incidents.sqlite")

        # ── state machine persistence ─────────────────────────────────────────
        from chp_core.types import StateMachineDefinition

        sm1 = SQLiteStateMachine(sm_path)
        defn = StateMachineDefinition(
            states=["draft", "review", "done"],
            transitions={"draft": ["review"], "review": ["done"]},
            initial_state="draft",
            terminal_states=["done"],
        )
        record = sm1.create("persistence-test", defn, {"env": "test"})
        sm1.transition(record.machine_id, "review")
        sm1.close()

        sm2 = SQLiteStateMachine(sm_path)
        reloaded = sm2.get(record.machine_id)
        assert reloaded is not None, "state machine not found after reopening store"
        assert reloaded.current_state == "review", (
            f"expected current_state='review', got {reloaded.current_state!r}"
        )
        assert len(reloaded.history) == 1, (
            f"expected 1 history entry, got {len(reloaded.history)}"
        )
        sm2.close()

        # ── incident persistence ──────────────────────────────────────────────
        mgr1 = SQLiteIncidentManager(inc_path)
        incident = mgr1.open("Persistence test", "P3")
        mgr1.escalate(incident.incident_id, note="testing")
        mgr1.close_conn()

        mgr2 = SQLiteIncidentManager(inc_path)
        reloaded_inc = mgr2.get(incident.incident_id)
        assert reloaded_inc is not None, "incident not found after reopening store"
        assert reloaded_inc.status == "escalated", (
            f"expected status='escalated', got {reloaded_inc.status!r}"
        )
        assert len(reloaded_inc.timeline) == 2, (
            f"expected 2 timeline entries, got {len(reloaded_inc.timeline)}"
        )
        mgr2.close_conn()


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
    ("metrics report", check_metrics_report),
    ("certification", check_certification),
    ("version control capability", check_version_control_capability),
    ("identity propagation", check_identity_propagation),
    ("composability declaration", check_composability_declaration),
    ("state machine capability", check_state_machine_capability),
    ("agent interface", check_agent_interface),
    ("safety capability", check_safety_capability),
    ("compliance capability", check_compliance_capability),
    ("incident capability", check_incident_capability),
    ("sqlite persistence", check_persistence),
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
