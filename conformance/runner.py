#!/usr/bin/env python3
"""Minimal CHP v0.1 conformance runner."""

from __future__ import annotations

import argparse
import asyncio
import uuid
import os
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
from sample_failing_hosts import (  # noqa: E402
    BrokenNoEvidenceHost,
    BrokenNoHashChainHost,
    BrokenNonStandardCodesHost,
)


Check = Callable[[Any], Awaitable[None]]


@dataclass(slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


# Per-run correlation namespace: the wire suite may run repeatedly against the
# SAME long-lived host, and stateful fixtures (the autonomy budget counts
# execution_started per correlation) would double-count under reused ids.
RUN = uuid.uuid4().hex[:6]


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
    from chp_core.policy import PolicyConfig  # noqa: PLC0415
    from chp_core.safety import RuleBasedSafetyEvaluator  # noqa: PLC0415
    from chp_core.types import GuardrailDefinition  # noqa: PLC0415

    # A fully-governed fixture: cap the allowed risk tier at 'medium' (a 'high'
    # capability is policy_blocked) and configure a safety guardrail that blocks
    # conformance.unsafe (safety_blocked). Explicit config (not load_policy())
    # keeps the fixture deterministic.
    evaluator = RuleBasedSafetyEvaluator(guardrails=[
        GuardrailDefinition(
            id="conformance-guardrail", capability_id_pattern="conformance.unsafe",
            max_risk_level="critical", requires_human_for=["conformance.unsafe"],
        ),
    ])
    host = LocalCapabilityHost(
        "conformance-host", store=SQLiteEvidenceStore(":memory:"),
        policy=PolicyConfig(max_risk_tier="medium"),
        safety_evaluator=evaluator,
    )

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
    # Governance fixtures (v0.2): an approval-gated and a budget-capped capability,
    # so approval/budget conformance is verifiable — including black-box over HTTP.
    from chp_core import AutonomyProfile  # noqa: PLC0415

    host.register(
        CapabilityDescriptor(
            id="conformance.approval", version="1.0.0",
            description="Approval-gated (every invocation requires approval).",
            autonomy=AutonomyProfile(tier="approval_required"),
        ),
        echo,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.budgeted", version="1.0.0",
            description="Budget-capped (action_limit=1 per correlation).",
            autonomy=AutonomyProfile(action_limit=1),
        ),
        echo,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.risky", version="1.0.0",
            description="High-risk (exceeds the host's max_risk_tier).",
            risk="high",
        ),
        echo,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.unsafe", version="1.0.0",
            description="Blocked by a safety guardrail.",
        ),
        echo,
    )

    async def stream(_ctx, _payload):
        from chp_core.types import StreamResult
        yield "s1"
        yield "s2"
        yield "s3"
        yield StreamResult({"chunks": 3, "joined": "s1s2s3"})

    host.register(
        CapabilityDescriptor(
            id="conformance.stream", version="1.0.0",
            description="Stream three deterministic chunks.",
            modes=["sync", "stream"],
        ),
        stream,
    )
    return host


async def check_declaration(host: Any) -> None:
    descriptor = host.discover()
    caps = descriptor.get("capabilities") or []
    # v0.2 is an additive superset of v0.1 (spec/README.md) — either is conformant.
    assert descriptor["protocol_version"] in ("0.1", "0.2")
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
        correlation={"correlation_id": f"{RUN}-conf-invoke"},
    )
    assert result_value(result, "success") is True
    assert result_value(result, "outcome") == "success"
    assert result_value(result, "data") == {"echo": "ok"}


async def check_correlation_propagation(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "corr"},
        correlation={"correlation_id": f"{RUN}-conf-correlation"},
    )
    correlation = result_value(result, "correlation")
    if isinstance(correlation, dict):
        correlation_id = correlation["correlation_id"]
    else:
        correlation_id = correlation.correlation_id
    assert correlation_id == f"{RUN}-conf-correlation"
    replay = host.replay(f"{RUN}-conf-correlation")
    assert replay
    assert {event["correlation"]["correlation_id"] for event in replay} == {f"{RUN}-conf-correlation"}


async def check_success_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "evidence"},
        correlation={"correlation_id": f"{RUN}-conf-success"},
    )
    assert len(evidence_ids(result)) >= 2
    event_types = [event["event_type"] for event in host.replay(f"{RUN}-conf-success")]
    assert "execution_started" in event_types
    assert "execution_completed" in event_types


async def check_failure_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.fail",
        {},
        correlation={"correlation_id": f"{RUN}-conf-failure"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "failure"
    event_types = [event["event_type"] for event in host.replay(f"{RUN}-conf-failure")]
    assert "execution_started" in event_types
    assert "execution_failed" in event_types


async def check_denial_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.guarded",
        {},
        correlation={"correlation_id": f"{RUN}-conf-denial"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "denied"
    event_types = [event["event_type"] for event in host.replay(f"{RUN}-conf-denial")]
    assert event_types == ["execution_denied"]


async def check_replay_by_correlation(host: Any) -> None:
    await invoke_host(
        host,
        "conformance.echo",
        {"value": "replay"},
        correlation={"correlation_id": f"{RUN}-conf-replay"},
    )
    replay = host.replay(f"{RUN}-conf-replay")
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
            "session_id": f"{RUN}-conf-pretool-001",
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
        events = store.by_correlation(f"{RUN}-conf-pretool-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-retrieval", store=store)
        cap = InMemoryKeywordRetrievalCapability(docs)
        register_retrieval_capability(host, cap)

        result = await host.ainvoke(
            "retrieval.query",
            {"query": "quick fox", "top_k": 2},
            correlation={"correlation_id": f"{RUN}-conf-retrieval-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay(f"{RUN}-conf-retrieval-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-ingestion", store=store)
        cap = InMemoryTextIngestionCapability()
        register_ingestion_capability(host, cap)

        result = await host.ainvoke(
            "ingestion.ingest",
            {"content": "the quick brown fox", "title": "Test Doc"},
            correlation={"correlation_id": f"{RUN}-conf-ingestion-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay(f"{RUN}-conf-ingestion-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-transformation", store=store)
        cap = InMemoryTextTransformationCapability()
        register_transformation_capability(host, cap)

        result = await host.ainvoke(
            "transformation.transform",
            {"content": "  Hello WORLD  ", "transform_type": "normalize"},
            correlation={"correlation_id": f"{RUN}-conf-transformation-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay(f"{RUN}-conf-transformation-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-graph", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)

        r1 = await host.ainvoke(
            "graph.add_entity",
            {"entity_id": "p1", "entity_type": "person", "label": "Alice"},
            correlation={"correlation_id": f"{RUN}-conf-graph-001"},
        )
        assert r1.success, f"add_entity failed: {r1}"

        r2 = await host.ainvoke(
            "graph.add_entity",
            {"entity_id": "p2", "entity_type": "person", "label": "Bob"},
            correlation={"correlation_id": f"{RUN}-conf-graph-001"},
        )
        assert r2.success, f"add_entity 2 failed: {r2}"

        r3 = await host.ainvoke(
            "graph.add_relation",
            {"from_entity_id": "p1", "to_entity_id": "p2", "relation_type": "knows"},
            correlation={"correlation_id": f"{RUN}-conf-graph-001"},
        )
        assert r3.success, f"add_relation failed: {r3}"

        r4 = await host.ainvoke(
            "graph.query_entities",
            {"entity_type": "person"},
            correlation={"correlation_id": f"{RUN}-conf-graph-001"},
        )
        assert r4.success, f"query_entities failed: {r4}"

        r5 = await host.ainvoke(
            "graph.traverse",
            {"start_id": "p1", "depth": 1},
            correlation={"correlation_id": f"{RUN}-conf-graph-001"},
        )
        assert r5.success, f"traverse failed: {r5}"

        events = host.replay(f"{RUN}-conf-graph-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-workflow", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)

        result = await host.ainvoke(
            "workflow.run",
            {
                "workflow_id": f"{RUN}-conf-wf-001",
                "name": "conformance-workflow",
                "steps": [
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "e1", "entity_type": "node"}},
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "e2", "entity_type": "node"}},
                ],
            },
            correlation={"correlation_id": f"{RUN}-conf-workflow-001"},
        )
        assert result.success, f"workflow.run failed: {result}"

        events = host.replay(f"{RUN}-conf-workflow-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-events", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)

        r1 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {"order_id": "o1"}},
            correlation={"correlation_id": f"{RUN}-conf-events-001"},
        )
        assert r1.success, f"events.emit 1 failed: {r1}"

        r2 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {"order_id": "o2"}},
            correlation={"correlation_id": f"{RUN}-conf-events-001"},
        )
        assert r2.success, f"events.emit 2 failed: {r2}"

        r3 = await host.ainvoke(
            "events.emit",
            {"event_type": "order.shipped", "source": "fulfillment", "data": {}},
            correlation={"correlation_id": f"{RUN}-conf-events-001"},
        )
        assert r3.success, f"events.emit 3 failed: {r3}"

        r4 = await host.ainvoke(
            "events.query",
            {"event_type": "order.placed"},
            correlation={"correlation_id": f"{RUN}-conf-events-001"},
        )
        assert r4.success, f"events.query failed: {r4}"

        events = host.replay(f"{RUN}-conf-events-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-metrics", store=store)
        cap = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, cap)

        corr = f"{RUN}-conf-metrics-001"
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
        host = LocalCapabilityHost(f"{RUN}-conf-vc", store=store)
        register_git_capabilities(host)

        repo_root = str(REPO_ROOT)
        result = await host.ainvoke(
            "chp.version_control.inspect_repo",
            {"repo_root": repo_root},
            correlation={"correlation_id": f"{RUN}-conf-vc-001"},
        )
        assert result.success, f"inspect_repo failed: {result}"

        events = host.replay(f"{RUN}-conf-vc-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-identity", store=store)

        async def _echo(ctx, payload):
            return {"ok": True}

        host.register(
            CapabilityDescriptor(id="identity.echo", version="1.0.0", description="Echo"),
            _echo,
        )

        subject = {"id": f"{RUN}-conf-agent", "type": "agent"}
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": f"{RUN}-conf-identity-001"},
            subject=subject,
        )

        events = host.replay(f"{RUN}-conf-identity-001")
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
        host = LocalCapabilityHost(f"{RUN}-conf-compose", store=store)

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
        host = LocalCapabilityHost(f"{RUN}-conf-sm", store=store)
        register_state_machine_capability(host, InMemoryStateMachine())

        corr = f"{RUN}-conf-sm-001"
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
        host = LocalCapabilityHost(f"{RUN}-conf-incident", store=store)
        register_incident_capability(host, InMemoryIncidentManager())

        corr = f"{RUN}-conf-incident-001"
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
        host = LocalCapabilityHost(f"{RUN}-conf-safety", store=store)
        register_safety_capability(host, RuleBasedSafetyEvaluator())

        corr = f"{RUN}-conf-safety-001"
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
        host = LocalCapabilityHost(f"{RUN}-conf-compliance", store=store)

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

        corr = f"{RUN}-conf-compliance-001"
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


async def check_standard_denial_codes(host: Any) -> None:
    """Invoking a missing capability produces the standard denial code 'capability_not_found'."""
    corr_id = f"{RUN}-conf-denial-codes-001"
    result = await invoke_host(host, "nonexistent.capability.xyz", {}, correlation={"correlation_id": corr_id})
    assert not result_value(result, "success"), "expected failure for missing capability"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    if isinstance(denial, dict):
        code = denial.get("code")
    else:
        code = getattr(denial, "code", None)
    assert code == "capability_not_found", (
        f"expected standard code 'capability_not_found', got {code!r}"
    )


async def check_input_schema_validation(_host: Any) -> None:
    """A capability with input_schema rejects non-conforming payloads before execution."""
    import tempfile, os
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost(f"{RUN}-conf-schema", store=store)

        async def handler(_ctx, _payload):
            return {"ok": True}

        host.register(
            CapabilityDescriptor(
                id="conf.typed",
                version="1.0.0",
                description="Typed capability.",
                input_schema={
                    "type": "object",
                    "properties": {"n": {"type": "integer"}},
                    "required": ["n"],
                    "additionalProperties": False,
                },
            ),
            handler,
        )

        bad = await host.ainvoke(
            "conf.typed",
            {"n": "not-an-integer"},
            correlation={"correlation_id": f"{RUN}-conf-schema-bad"},
        )
        assert not bad.success, "expected denial for invalid payload"
        assert bad.outcome == "denied", f"expected denied, got {bad.outcome!r}"
        assert bad.denial.code == "input_schema_validation_failed", (
            f"expected 'input_schema_validation_failed', got {bad.denial.code!r}"
        )

        good = await host.ainvoke(
            "conf.typed",
            {"n": 42},
            correlation={"correlation_id": f"{RUN}-conf-schema-good"},
        )
        assert good.success, f"valid payload should succeed, got: {good}"
        store.close()
    finally:
        os.unlink(store_path)


def _assert_hash_chain(events: list[Any]) -> None:
    """Shared assertion: events must carry content_hash and link via prev_hash."""
    assert len(events) >= 2, f"expected at least 2 events, got {len(events)}"
    for ev in events:
        assert "content_hash" in ev, f"missing content_hash in event seq={ev.get('sequence')}"
        assert isinstance(ev["content_hash"], str) and len(ev["content_hash"]) == 64, (
            f"content_hash must be a 64-char hex string, got {ev['content_hash']!r}"
        )
    second = events[1]
    assert "prev_hash" in second, "second event must have prev_hash linking to first"
    assert second["prev_hash"] == events[0]["content_hash"], (
        "prev_hash of second event must equal content_hash of first"
    )


async def check_evidence_hash_chain(host: Any) -> None:
    """Evidence events carry SHA256 content_hash + prev_hash to form a tamper-detectable chain."""
    corr_id = f"{RUN}-conf-chain-001"

    if hasattr(host, "by_correlation_with_hashes"):
        # Host exposes hash-aware replay — test it directly (catches BrokenNoHashChainHost)
        await invoke_host(host, "conformance.echo", {"value": "integrity-check"}, correlation={"correlation_id": corr_id})
        events = host.by_correlation_with_hashes(corr_id)
        _assert_hash_chain(events)
    else:
        # Fall back: create an isolated reference host and verify the SQLiteEvidenceStore chain
        import tempfile, os
        from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            store_path = f.name
        try:
            store = SQLiteEvidenceStore(store_path)
            ref_host = LocalCapabilityHost(f"{RUN}-conf-chain", store=store)

            async def echo(_ctx, payload):
                return {"echo": payload.get("value")}

            ref_host.register(CapabilityDescriptor(id="conf.chain.echo", version="1.0.0", description=""), echo)
            await ref_host.ainvoke("conf.chain.echo", {"value": "integrity-check"}, correlation={"correlation_id": corr_id})
            events = store.by_correlation_with_hashes(corr_id)
            _assert_hash_chain(events)
            chain_result = store.verify_chain(corr_id)
            assert chain_result.valid, f"hash chain should be valid, got: {chain_result}"
            store.close()
        finally:
            os.unlink(store_path)


async def check_signed_evidence_bundle(_host: Any) -> None:
    """v0.2: a host can export a signed evidence bundle that verifies offline,
    and any tampering is detected."""
    import tempfile, os
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core import signing

    if not signing.signing_available():
        return  # signing is an optional tier; nothing to assert without the backend

    with tempfile.TemporaryDirectory() as d:
        store = SQLiteEvidenceStore(os.path.join(d, "ev.sqlite"))
        host = LocalCapabilityHost(f"{RUN}-conf-sign", store=store)

        async def echo(_ctx, payload):
            return {"echo": payload.get("value")}

        host.register(CapabilityDescriptor(id="conf.sign.echo", version="1.0.0", description=""), echo)
        await host.ainvoke("conf.sign.echo", {"value": "v"}, correlation={"correlation_id": "cs"})

        key = signing.generate_keypair(os.path.join(d, "keys"))
        events = store.export_correlation("cs")
        bundle = signing.sign_bundle(signing.build_bundle(f"{RUN}-conf-sign", events, created_at="2026-01-01T00:00:00Z"), key)
        store.close()

        assert signing.verify_bundle(bundle, expected_key_id=key.key_id).valid, "signed bundle must verify"
        tampered = dict(bundle)
        tampered["events"] = [dict(e) for e in bundle["events"]]
        tampered["events"][0]["payload"] = {"value": "TAMPERED"}
        assert not signing.verify_bundle(tampered).valid, "tampered bundle must fail verification"


async def check_strict_verify_rejects_unhashed(_host: Any) -> None:
    """v0.2: strict verification fails on a legacy unhashed event; lenient tolerates it."""
    import tempfile, os
    from chp_core import SQLiteEvidenceStore

    with tempfile.TemporaryDirectory() as d:
        store = SQLiteEvidenceStore(os.path.join(d, "ev.sqlite"))
        with store._lock:
            store._conn.execute("INSERT INTO evidence_sequence DEFAULT VALUES")
            store._conn.execute(
                "INSERT INTO evidence_events (sequence,event_id,event_type,invocation_id,"
                "capability_id,host_id,correlation_id,timestamp,payload_json,event_json,"
                "content_hash,prev_hash) VALUES (1,'e','execution_started','i','c','h','cx','t','{}','{}',NULL,NULL)"
            )
            store._conn.commit()
        assert store.verify_chain("cx").valid, "lenient must tolerate legacy unhashed events"
        assert not store.verify_chain("cx", strict=True).valid, "strict must reject unhashed events"
        store.close()


async def check_retention_preserves_chain(_host: Any) -> None:
    """v0.2: retention prunes whole old correlations without breaking a survivor's chain."""
    import tempfile, os
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.compliance import SQLiteComplianceManager
    from chp_core.types import RetentionPolicy

    with tempfile.TemporaryDirectory() as d:
        store = SQLiteEvidenceStore(os.path.join(d, "ev.sqlite"))
        host = LocalCapabilityHost(f"{RUN}-conf-ret", store=store)

        async def noop(_ctx, _p):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="conf.ret.noop", version="1.0.0", description=""), noop)
        for cid in ("old", "keep"):
            await host.ainvoke("conf.ret.noop", {}, correlation={"correlation_id": cid})
            await host.ainvoke("conf.ret.noop", {}, correlation={"correlation_id": cid})
        with store._lock:
            store._conn.execute("UPDATE evidence_events SET timestamp='2020-01-01T00:00:00Z' WHERE correlation_id='old'")
            store._conn.commit()

        SQLiteComplianceManager(store).apply_retention([
            RetentionPolicy(policy_id="p", applies_to=["*"], retain_days=365)
        ])
        assert store.count_by_correlation("old") == 0, "fully-old correlation must be pruned"
        assert store.count_by_correlation("keep") == 4, "recent correlation must survive intact"
        assert store.verify_chain("keep").valid, "survivor chain must still verify after prune"
        store.close()


async def check_approval_required_governance(host: Any) -> None:
    """v0.2 governance (chp-governance-v0.2.md §4.1): a capability whose autonomy
    tier is 'approval_required' is denied with the reserved code
    'approval_required', emits 'approval_requested' BEFORE denying, and does NOT
    start execution. The human-in-the-loop differentiator — guarded so a host
    can't silently drop the approval evidence and still claim conformance.
    Uses the fixture profile's conformance.approval, so it holds black-box too."""
    result = await invoke_host(
        host, "conformance.approval", {}, correlation={"correlation_id": f"{RUN}-conf-approval-001"}
    )
    assert not result_value(result, "success"), f"approval-gated must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "approval_required", f"expected 'approval_required', got {code!r}"
    types = [e["event_type"] for e in host.replay(f"{RUN}-conf-approval-001")]
    assert "approval_requested" in types, f"approval_requested not emitted: {types}"
    assert "execution_started" not in types, "gated capability must not begin execution"


async def check_budget_exceeded_governance(host: Any) -> None:
    """v0.2 governance (§4.1): once an autonomy action_limit is exhausted, further
    invocations on that correlation are denied with the reserved code
    'budget_exceeded' and a 'budget_exceeded' event — the autonomy-budget
    differentiator. The invocation before the limit still succeeds. Uses the
    fixture profile's conformance.budgeted (action_limit=1)."""
    corr = {"correlation_id": f"{RUN}-conf-budget-001"}
    first = await invoke_host(host, "conformance.budgeted", {}, correlation=corr)
    assert result_value(first, "success"), f"first invocation (within budget) must succeed: {first}"
    second = await invoke_host(host, "conformance.budgeted", {}, correlation=corr)
    assert not result_value(second, "success"), f"over-budget invocation must be denied: {second}"
    assert result_value(second, "outcome") == "denied", (
        f"expected 'denied', got {result_value(second, 'outcome')!r}"
    )
    denial = result_value(second, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "budget_exceeded", f"expected 'budget_exceeded', got {code!r}"
    types = [e["event_type"] for e in host.replay(f"{RUN}-conf-budget-001")]
    assert "budget_exceeded" in types, f"budget_exceeded event not emitted: {types}"


async def check_risk_tier_governance(host: Any) -> None:
    """v0.2 governance (chp-governance-v0.2.md §3): a capability whose risk tier
    orders above the host's max_risk_tier is denied with the reserved code
    'policy_blocked'. The risk-tier differentiator — guarded. Uses the fixture
    profile's conformance.risky ('high') against a host capped at 'medium'."""
    result = await invoke_host(
        host, "conformance.risky", {}, correlation={"correlation_id": f"{RUN}-conf-risk-001"}
    )
    assert not result_value(result, "success"), f"over-tier capability must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "policy_blocked", f"expected 'policy_blocked', got {code!r}"
    types = [e["event_type"] for e in host.replay(f"{RUN}-conf-risk-001")]
    assert "execution_started" not in types, "over-tier capability must not begin execution"


async def check_safety_governance(host: Any) -> None:
    """v0.2 governance (chp-governance-v0.2.md §4.2): with a safety evaluator
    configured, an invocation a guardrail blocks is denied with the reserved
    'safety_blocked' code, records the assessment pair (started/completed) and
    safety_action_blocked, and never starts execution. The safety differentiator
    — a signed safety verdict on the governed plane, guarded. Uses the fixture
    profile's conformance.unsafe."""
    result = await invoke_host(
        host, "conformance.unsafe", {}, correlation={"correlation_id": f"{RUN}-conf-safety-001"}
    )
    assert not result_value(result, "success"), f"guardrail-blocked must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "safety_blocked", f"expected 'safety_blocked', got {code!r}"
    types = [e["event_type"] for e in host.replay(f"{RUN}-conf-safety-001")]
    for required in ("safety_assessment_started", "safety_assessment_completed",
                     "safety_action_blocked"):
        assert required in types, f"missing {required}: {types}"
    assert "execution_started" not in types, "blocked capability must not begin execution"


async def check_export_bundle(host: Any) -> None:
    """v0.2 (binding §4a): GET /export/{corr} returns this host's evidence
    bundle for the correlation, offline-verifiable — signed when the host holds
    a key, hash-chain tier otherwise. The export IS the federation primitive:
    task bundles aggregate exactly these."""
    corr = f"{RUN}-conf-export-001"
    await invoke_host(host, "conformance.echo", {"value": "x"},
                      correlation={"correlation_id": corr})
    bundle = host.export_bundle(corr)
    assert bundle.get("events"), f"exported bundle has no events: {list(bundle)}"
    assert bundle.get("canonicalization") == "chp-stable-v1", bundle.get("canonicalization")
    from chp_core.signing import verify_bundle
    v = verify_bundle(bundle)
    assert v.valid, f"exported bundle does not verify: {v.reason}"
    assert v.assurance in ("hash-chain", "signed"), v.assurance


async def check_identity_document(host: Any) -> None:
    """v0.2 (spec §3.1): the host serves its public identity document at
    /.well-known/chp-identity — unauthenticated, so a never-met verifier can
    resolve the key. Declares an assurance tier; at the signed tier the
    self-attestation must verify (and any anchors ride inside it)."""
    doc = host.identity()
    assert doc.get("assurance") in ("none", "hash-chain", "signed"), (
        f"identity doc must declare an assurance tier: {doc}"
    )
    if doc.get("assurance") == "signed":
        assert doc.get("key_id") and doc.get("public_key"), f"signed tier must expose the key: {doc}"
        att = doc.get("host_identity")
        if att:
            from chp_core.signing import verify_attestation
            assert verify_attestation(att, public_key=doc["public_key"]), (
                "identity attestation does not verify under the presented key"
            )


async def check_wire_verify(host: Any) -> None:
    """v0.2 over the wire: after an invocation, GET /verify/{corr} confirms the
    host's own chain is intact (or, in gateway mode, says so honestly)."""
    corr = f"{RUN}-conf-wire-verify"
    await invoke_host(host, "conformance.echo", {"value": "v"}, correlation={"correlation_id": corr})
    result = host.verify(corr)
    if "valid" in result:
        assert result["valid"] is True, f"host /verify reported an invalid chain: {result}"
    else:
        # Gateway mode: no local store — must say so, not claim validity.
        assert "note" in result, f"/verify returned neither 'valid' nor a gateway 'note': {result}"


# The NORMATIVE suite = the spec's MUST behaviors. Passing THIS is what
# "spec-conformant CHP host" means — it does NOT require shipping the reference
# capability library. (Previously the two were mixed, so a spec-perfect host
# that omitted the reference RAG/graph/workflow capabilities failed ~half the
# runner. That redefined "conforming" as "ships our library"; this split undoes
# it.) See spec/chp-v0.1.md §11 + chp-v0.2.md.
NORMATIVE_CHECKS: list[tuple[str, Check]] = [
    ("capability declaration", check_declaration),
    ("capability discovery", check_discovery),
    ("invocation through envelope", check_invocation_envelope),
    ("correlation propagation", check_correlation_propagation),
    ("evidence emission on success", check_success_evidence),
    ("evidence emission on failure", check_failure_evidence),
    ("evidence emission on denial", check_denial_evidence),
    ("replay by correlation id", check_replay_by_correlation),
    ("identity propagation", check_identity_propagation),
    ("standard denial codes", check_standard_denial_codes),
    ("input schema validation", check_input_schema_validation),
    ("approval-required governance (v0.2)", check_approval_required_governance),
    ("budget-exceeded governance (v0.2)", check_budget_exceeded_governance),
    ("risk-tier governance (v0.2)", check_risk_tier_governance),
    ("safety-guardrail governance (v0.2)", check_safety_governance),
    ("sqlite persistence", check_persistence),
    ("evidence hash chain", check_evidence_hash_chain),
    ("signed evidence bundle (v0.2)", check_signed_evidence_bundle),
    ("strict verify rejects unhashed (v0.2)", check_strict_verify_rejects_unhashed),
    ("retention preserves chain (v0.2)", check_retention_preserves_chain),
]

# The REFERENCE suite exercises the bundled reference capability library. These
# are NOT protocol MUSTs — a conforming host need not ship them. They gate the
# reference implementation's quality, not spec conformance.
REFERENCE_CHECKS: list[tuple[str, Check]] = [
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
    ("composability declaration", check_composability_declaration),
    ("state machine capability", check_state_machine_capability),
    ("agent interface", check_agent_interface),
    ("safety capability", check_safety_capability),
    ("compliance capability", check_compliance_capability),
    ("incident capability", check_incident_capability),
]

# The WIRE suite = the normative behaviours observable over the HTTP binding
# (spec/chp-http-binding.md §5), driving a running host through the reference
# RemoteCapabilityHost client. It's the subset of NORMATIVE_CHECKS that needs
# only the wire surface (discover / invoke / replay / verify) — the checks that
# reach into a local SQLite store can't run black-box. A host-under-test
# pre-registers the fixture profile (conformance.echo/fail/guarded).
async def check_scoped_caller_key(host: Any) -> None:
    """v0.2 (binding §2): a capability-scoped caller key. In-scope invokes
    succeed under the scoped verified subject; an out-of-scope invocation is a
    PROCESSED governance denial — HTTP 200, outcome `denied`, reserved code
    `policy_blocked` — never a bare transport 403. The host-under-test
    configures `conformance-scoped:<key>:conformance.echo` (FIXTURES.md) and
    the runner receives the key via CHP_CONFORMANCE_SCOPED_KEY."""
    scoped_key = os.environ.get("CHP_CONFORMANCE_SCOPED_KEY")
    assert scoped_key, (
        "scoped-key check needs CHP_CONFORMANCE_SCOPED_KEY (a key configured as "
        "conformance-scoped:<key>:conformance.echo on the host under test)"
    )
    from chp_core.http import RemoteCapabilityHost
    base = getattr(host, "_base", None)
    assert base, "scoped-key check requires a wire host"
    scoped = RemoteCapabilityHost(base, api_key=scoped_key)

    ok = await invoke_host(scoped, "conformance.echo", {"value": "in-scope"})
    assert result_value(ok, "outcome") == "success", f"in-scope invoke failed: {ok}"

    denied = await invoke_host(scoped, "conformance.fail", {})
    assert result_value(denied, "outcome") == "denied", (
        f"out-of-scope invoke must be a PROCESSED denial (200 + outcome denied), got: {denied}"
    )
    denial = result_value(denied, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "policy_blocked", f"out-of-scope denial must use policy_blocked, got {code!r}"


def _denial_code(result: Any) -> Any:
    denial = result_value(result, "denial")
    return denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)


async def check_mandate_gate(host: Any) -> None:
    """v0.2 §10 (pipeline gate 5): delegated authority on the wire. The runner
    plays PRINCIPAL with a fresh in-memory key — the host under test has never
    met it (verification is offline; principal pinning is a MAY). A valid,
    in-scope mandate succeeds and the evidence subject becomes the delegate
    acting under the principal's authority; out-of-scope → policy_blocked;
    expired or tampered → mandate_invalid. All PROCESSED denials, never 403."""
    import base64
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from chp_core import signing

    # Whose name must the mandate carry? Probe: a transport-authenticated
    # connection binds a verified caller the mandate MUST name as delegate;
    # an unauthenticated one accepts any delegate name.
    probe = await invoke_host(host, "conformance.echo", {"value": "probe"},
                              correlation={"correlation_id": f"{RUN}-conf-mandate-probe"})
    assert result_value(probe, "outcome") == "success", f"probe invoke failed: {probe}"
    probe_subj = (host.replay(f"{RUN}-conf-mandate-probe")[0].get("subject") or {})
    delegate = probe_subj.get("id") if probe_subj.get("verified") else "conformance-runner"

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    key = signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                          public_key_b64=pub, _private=priv)
    now = datetime.now(timezone.utc)

    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _mandate(scope: list[str], hours: float = 1) -> dict:
        return signing.build_mandate(
            "conformance-principal", key, delegate_id=delegate, scope=scope,
            valid_from=_iso(now - timedelta(minutes=1)),
            valid_until=_iso(now + timedelta(hours=hours)),
            created_at=_iso(now))

    # 1. Valid + in-scope → success; the signed chain carries the mandate subject.
    ok = await invoke_host(host, "conformance.echo", {"value": "mandated"},
                           correlation={"correlation_id": f"{RUN}-conf-mandate-ok"},
                           mandate=_mandate(["conformance.echo"]))
    assert result_value(ok, "outcome") == "success", f"mandated invoke failed: {ok}"
    subj = (host.replay(f"{RUN}-conf-mandate-ok")[0].get("subject") or {})
    assert subj.get("type") == "mandate" and subj.get("verified") is True, (
        f"evidence subject must be the mandate binding, got: {subj}")
    assert subj.get("id") == delegate and subj.get("principal") == "conformance-principal", (
        f"mandate subject must name delegate + principal, got: {subj}")

    # 2. Out-of-scope capability → PROCESSED policy_blocked (§2 semantics).
    denied = await invoke_host(host, "conformance.fail", {},
                               mandate=_mandate(["conformance.echo"]))
    assert result_value(denied, "outcome") == "denied", f"out-of-scope must deny: {denied}"
    assert _denial_code(denied) == "policy_blocked", (
        f"out-of-mandate-scope must be policy_blocked, got {_denial_code(denied)!r}")

    # 3. Expired mandate → mandate_invalid (never becomes valid again).
    expired = await invoke_host(host, "conformance.echo", {"value": "late"},
                                mandate=_mandate(["conformance.echo"], hours=-1))
    assert _denial_code(expired) == "mandate_invalid", (
        f"expired mandate must be mandate_invalid, got {_denial_code(expired)!r}")

    # 4. Tampered mandate (scope widened after signing) → mandate_invalid.
    bad = _mandate(["conformance.echo"])
    bad["scope"] = ["*"]
    tampered = await invoke_host(host, "conformance.echo", {"value": "x"}, mandate=bad)
    assert _denial_code(tampered) == "mandate_invalid", (
        f"tampered mandate must be mandate_invalid, got {_denial_code(tampered)!r}")


async def check_sub_delegation(host: Any) -> None:
    """v0.2 §10 Sub-delegation (proposal 0009): attenuation-only mandate chains.
    The runner plays ROOT principal, an intermediate re-delegates a NARROWED
    slice to the caller, and the host walks the chain: a valid chain succeeds
    with the root principal in the evidence subject; a widened-scope or
    lengthened-window chain is mandate_invalid; revoking the ROOT kills the
    sub."""
    import base64
    import json as _json
    import urllib.error
    import urllib.request
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from chp_core import signing
    from chp_core.types import utc_now

    probe = await invoke_host(host, "conformance.echo", {"value": "probe"},
                              correlation={"correlation_id": f"{RUN}-conf-subdel-probe"})
    assert result_value(probe, "outcome") == "success", f"probe failed: {probe}"
    probe_subj = (host.replay(f"{RUN}-conf-subdel-probe")[0].get("subject") or {})
    caller = probe_subj.get("id") if probe_subj.get("verified") else "conformance-runner"

    def _key():
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                               public_key_b64=pub, _private=priv)

    root_key, mid_key = _key(), _key()
    now = datetime.now(timezone.utc)

    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    root = signing.build_mandate(
        "subdel-root", root_key, delegate_id="subdel-middle",
        scope=["conformance.echo", "conformance.other"],
        valid_from=_iso(now - timedelta(minutes=1)),
        valid_until=_iso(now + timedelta(hours=2)), created_at=_iso(now))

    def _sub(scope, hours=1):
        return signing.build_sub_mandate(
            root, mid_key, delegate_id=caller, scope=scope,
            valid_from=_iso(now - timedelta(minutes=1)),
            valid_until=_iso(now + timedelta(hours=hours)), created_at=_iso(now))

    # 1. Valid narrowed chain → success; the subject records the ROOT principal.
    sub = _sub(["conformance.echo"])
    ok = await invoke_host(host, "conformance.echo", {"value": "chained"},
                           correlation={"correlation_id": f"{RUN}-conf-subdel-ok"},
                           mandate=sub)
    assert result_value(ok, "outcome") == "success", f"valid chain failed: {ok}"
    subj = (host.replay(f"{RUN}-conf-subdel-ok")[0].get("subject") or {})
    assert subj.get("id") == caller and subj.get("principal") == "subdel-middle", (
        f"subject must bind the leaf delegate under its immediate principal: {subj}")
    assert subj.get("root_principal") == "subdel-root", (
        f"subject must record the chain's root principal: {subj}")

    # 2. Widened scope (tampered after signing) → mandate_invalid.
    widened = _sub(["conformance.echo"])
    widened["scope"] = ["conformance.echo", "conformance.other"]  # broader than the sub granted
    dw = await invoke_host(host, "conformance.echo", {"value": "x"}, mandate=widened)
    assert _denial_code(dw) == "mandate_invalid", (
        f"a widened chain must be mandate_invalid, got {_denial_code(dw)!r}")

    # 3. Lengthened window (re-signed so the leaf signature passes) →
    # mandate_invalid on attenuation_window.
    longer = _sub(["conformance.echo"])
    longer["valid_until"] = _iso(now + timedelta(hours=10))  # beyond the root's 2h
    longer["signature"]["signature"] = signing._sign(
        mid_key._private, signing._canon(signing.mandate_header(longer)))
    dl = await invoke_host(host, "conformance.echo", {"value": "x"}, mandate=longer)
    assert _denial_code(dl) == "mandate_invalid", (
        f"a lengthened-window chain must be mandate_invalid, got {_denial_code(dl)!r}")

    # 4. Revoke the ROOT → the sub is now mandate_invalid (suffix-kill). Only a
    # wire host exposes /revocations; skip the revocation leg otherwise.
    base = getattr(host, "_base", None)
    if base:
        api_key = getattr(host, "_api_key", None)
        rev = signing.build_mandate_revocation(root, root_key, revoked_at=utc_now())
        req = urllib.request.Request(
            f"{base}/revocations", data=_json.dumps(rev).encode(),
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            assert _json.loads(resp.read())["accepted"] is True
        revoked = await invoke_host(host, "conformance.echo", {"value": "x"},
                                    mandate=_sub(["conformance.echo"]))
        assert _denial_code(revoked) == "mandate_invalid", (
            f"revoking the root must kill the sub, got {_denial_code(revoked)!r}")


async def check_witness_roundtrip(host: Any) -> None:
    """v0.2 §12: the witness exchange. The runner plays WITNESS with a fresh
    key the host has never met: GET /head → sign a chain-witness statement →
    POST /witness (the host must verify + accept) → GET /witnesses serves it.
    The sequence must be monotonic across an invocation, and a statement over
    a WRONG head must be refused (409) — never silently stored."""
    import base64
    import json as _json
    import urllib.error
    import urllib.request

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from chp_core import signing
    from chp_core.types import utc_now

    base = getattr(host, "_base", None)
    assert base, "witness check requires a wire host"
    api_key = getattr(host, "_api_key", None)

    def _req(path: str, body=None):
        req = urllib.request.Request(
            f"{base}{path}",
            data=_json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})},
            method="POST" if body is not None else "GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.loads(resp.read().decode())

    head = _req("/head")
    assert head.get("scheme") == "chp-store-head-v1", f"unknown head scheme: {head}"
    assert isinstance(head.get("sequence"), int) and head.get("store_head"), head

    # Sequence monotonicity across an invocation.
    await invoke_host(host, "conformance.echo", {"value": "witnessed"})
    head2 = _req("/head")
    assert head2["sequence"] > head["sequence"], (
        "the store sequence must advance across an invocation")

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    key = signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                          public_key_b64=pub, _private=priv)

    stmt = signing.build_chain_witness(
        str(head2["host_id"]), int(head2["sequence"]), str(head2["store_head"]),
        key, witness_id="conformance-witness", witnessed_at=utc_now())
    accepted = _req("/witness", stmt)
    assert accepted.get("accepted") is True, f"witness must be accepted: {accepted}"

    served = _req("/witnesses")
    heads = [w.get("store_head") for w in served.get("witnesses", [])]
    assert head2["store_head"] in heads, "the accepted witness must be served back"

    # A statement over a WRONG head must be refused, never stored.
    bad = signing.build_chain_witness(
        str(head2["host_id"]), int(head2["sequence"]), "0" * 64,
        key, witness_id="conformance-witness", witnessed_at=utc_now())
    try:
        _req("/witness", bad)
        raise AssertionError("a wrong-head witness must be refused")
    except urllib.error.HTTPError as exc:
        assert exc.code in (400, 409), f"expected 400/409 refusal, got {exc.code}"


async def check_mandate_revocation(host: Any) -> None:
    """v0.2 §10 Revocation (proposal 0007): withdrawing authority before
    expiry. The runner plays PRINCIPAL: a mandated invoke succeeds; the
    principal's revocation POSTs and is served back; the SAME mandate is now
    a PROCESSED mandate_invalid denial. A forged revocation — another key
    impersonating the principal block — must be inert: refused at POST or,
    if the impostor self-signs consistently, accepted-but-never-revoking
    (the issuer-only key match at gate 5 is the real defense)."""
    import base64
    import json as _json
    import urllib.error
    import urllib.request
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from chp_core import signing
    from chp_core.types import utc_now

    base = getattr(host, "_base", None)
    assert base, "revocation check requires a wire host"
    api_key = getattr(host, "_api_key", None)

    def _req(path: str, body=None):
        req = urllib.request.Request(
            f"{base}{path}",
            data=_json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})},
            method="POST" if body is not None else "GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.loads(resp.read().decode())

    def _fresh_key():
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                               public_key_b64=pub, _private=priv)

    probe = await invoke_host(host, "conformance.echo", {"value": "probe"},
                              correlation={"correlation_id": f"{RUN}-conf-rev-probe"})
    assert result_value(probe, "outcome") == "success", f"probe invoke failed: {probe}"
    probe_subj = (host.replay(f"{RUN}-conf-rev-probe")[0].get("subject") or {})
    delegate = probe_subj.get("id") if probe_subj.get("verified") else "conformance-runner"

    key = _fresh_key()
    now = datetime.now(timezone.utc)

    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _mandate(k) -> dict:
        return signing.build_mandate(
            "conformance-principal", k, delegate_id=delegate,
            scope=["conformance.echo"],
            valid_from=_iso(now - timedelta(minutes=1)),
            valid_until=_iso(now + timedelta(hours=1)),
            created_at=_iso(now))

    mandate = _mandate(key)

    # 1. The mandate works before revocation.
    ok = await invoke_host(host, "conformance.echo", {"value": "pre-revocation"},
                           mandate=mandate)
    assert result_value(ok, "outcome") == "success", f"mandated invoke failed: {ok}"

    # 2. The principal revokes; the host verifies, persists, serves it back.
    stmt = signing.build_mandate_revocation(
        mandate, key, revoked_at=utc_now(), reason="conformance")
    accepted = _req("/revocations", stmt)
    assert accepted.get("accepted") is True, f"revocation must be accepted: {accepted}"
    served = _req("/revocations")
    assert mandate["mandate_id"] in [m.get("mandate_id")
                                     for m in served.get("mandates", [])], (
        "the accepted revocation must be served back")

    # 3. The SAME mandate is now mandate_invalid (PROCESSED, HTTP 200).
    denied = await invoke_host(host, "conformance.echo", {"value": "post-revocation"},
                               mandate=mandate)
    assert result_value(denied, "outcome") == "denied", (
        f"revoked mandate must deny: {denied}")
    assert _denial_code(denied) == "mandate_invalid", (
        f"revoked mandate must be mandate_invalid, got {_denial_code(denied)!r}")

    # 4a. A TAMPERED statement (broken signature) is refused, never stored.
    fresh = _mandate(key)
    bad = signing.build_mandate_revocation(fresh, key, revoked_at=utc_now())
    bad["mandate_id"] = "mnd_retargeted"
    try:
        _req("/revocations", bad)
        raise AssertionError("an unverifiable revocation must be refused")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400, f"expected 400 refusal, got {exc.code}"

    # 4b. A FORGED statement (impostor key, self-consistent) must be inert:
    # whatever the host does at POST, the fresh mandate keeps working.
    impostor = _fresh_key()
    impostor_mandate = signing.build_mandate(
        "conformance-principal", impostor, delegate_id=delegate,
        scope=["conformance.echo"],
        valid_from=fresh["valid_from"], valid_until=fresh["valid_until"],
        created_at=fresh["created_at"], mandate_id=fresh["mandate_id"])
    forged = signing.build_mandate_revocation(
        impostor_mandate, impostor, revoked_at=utc_now(), reason="forgery attempt")
    try:
        _req("/revocations", forged)
    except urllib.error.HTTPError:
        pass  # refusing a forgery outright is also conformant
    still_ok = await invoke_host(host, "conformance.echo", {"value": "not-revoked"},
                                 mandate=fresh)
    assert result_value(still_ok, "outcome") == "success", (
        "a revocation signed by a non-issuer key must revoke NOTHING "
        f"(issuer-only rule): {still_ok}")


async def check_streaming_invocation(host: Any) -> None:
    """Proposal 0006 on the wire (binding "Streaming invocations"):
    mode:"stream" answers text/event-stream with `chunk` frames and exactly
    one terminal `result` frame carrying a standard InvocationResult — and a
    DENIED streaming invoke answers plain JSON (a denial never commits to
    SSE; the client switches on Content-Type). Sync-mode invocation of the
    streaming fixture degrades gracefully."""
    import json as _json
    import urllib.request

    base = getattr(host, "_base", None)
    assert base, "streaming check requires a wire host"
    api_key = getattr(host, "_api_key", None)

    def _post_raw(body: dict):
        req = urllib.request.Request(
            f"{base}/invoke", data=_json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})},
            method="POST")
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.headers.get("Content-Type", ""), resp.read().decode()

    # 1. Streaming success: SSE with chunk frames + one terminal result frame.
    ctype, raw = _post_raw({"capability_id": "conformance.stream",
                            "mode": "stream", "payload": {}})
    assert "text/event-stream" in ctype, (
        f"mode=stream must answer text/event-stream, got {ctype!r}")
    chunks: list = []
    result = None
    event = None
    for line in raw.splitlines():
        if line.startswith("event: "):
            event = line[len("event: "):].strip()
        elif line.startswith("data: "):
            data = _json.loads(line[len("data: "):])
            if event == "chunk":
                chunks.append(data.get("delta"))
            elif event == "result":
                assert result is None, "exactly ONE terminal result frame"
                result = data
    assert chunks == ["s1", "s2", "s3"], f"expected the fixture chunks, got {chunks}"
    assert result is not None, "the stream must end with a result frame"
    assert result.get("outcome") == "success", f"terminal result must succeed: {result}"
    assert (result.get("data") or {}).get("joined") == "s1s2s3", (
        f"terminal result carries the assembled data: {result.get('data')}")

    # 2. A DENIED streaming invoke stays plain JSON (never commits to SSE).
    ctype, raw = _post_raw({"capability_id": "conformance.unsafe",
                            "mode": "stream", "payload": {}})
    assert "application/json" in ctype, (
        f"a denial must never commit to SSE, got {ctype!r}")
    denied = _json.loads(raw)
    assert denied.get("outcome") == "denied", f"expected processed denial: {denied}"

    # 3. Sync-mode invocation of the streaming fixture degrades gracefully.
    sync = await invoke_host(host, "conformance.stream", {})
    assert result_value(sync, "outcome") == "success", f"sync degrade failed: {sync}"
    data = result_value(sync, "data") or {}
    assert data.get("joined") == "s1s2s3", f"sync mode returns the terminal data: {data}"


async def check_idempotent_replay(host: Any) -> None:
    """v0.2 §13 (proposal 0008): a host that already recorded an
    invocation_id replays the RECORDED result — identical data, marked
    `replayed: true`, exactly ONE execution in evidence. A replayed denial
    is the same denial. A fresh id always executes fresh."""
    import json as _json
    import urllib.request

    base = getattr(host, "_base", None)
    assert base, "idempotent-replay check requires a wire host"
    api_key = getattr(host, "_api_key", None)

    def _post_invoke(body: dict) -> dict:
        req = urllib.request.Request(
            f"{base}/invoke", data=_json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})},
            method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _json.loads(resp.read().decode())

    # 1. Same id twice → identical recorded data, replayed marker, ONE execution.
    corr = f"{RUN}-conf-replay-1"
    body = {"capability_id": "conformance.echo",
            "payload": {"value": f"nonce-{RUN}"},
            "invocation_id": f"inv-{RUN}-replay-1",
            "correlation": {"correlation_id": corr}}
    first = _post_invoke(dict(body))
    second = _post_invoke(dict(body))
    assert first.get("outcome") == "success", f"first invoke failed: {first}"
    assert second.get("outcome") == "success", f"replay failed: {second}"
    assert first.get("data") == second.get("data"), (
        "replay must return the RECORDED data verbatim")
    assert "replayed" not in first, "a fresh execution must omit the replayed marker"
    assert second.get("replayed") is True, (
        f"a replayed result must carry replayed: true — got {second}")
    events = host.replay(corr)
    starts = sum(1 for e in events if e.get("event_type") == "execution_started")
    assert starts == 1, f"replay must not re-execute (execution_started × {starts})"

    # 2. A denial replays as the SAME denial, with no second denial event.
    corr_d = f"{RUN}-conf-replay-denied"
    body_d = {"capability_id": "conformance.risky", "payload": {},
              "invocation_id": f"inv-{RUN}-replay-denied",
              "correlation": {"correlation_id": corr_d}}
    d1 = _post_invoke(dict(body_d))
    d2 = _post_invoke(dict(body_d))
    assert d1.get("outcome") == "denied" and d2.get("outcome") == "denied"
    assert (d2.get("denial") or {}).get("code") == (d1.get("denial") or {}).get("code")
    assert d2.get("replayed") is True
    denies = sum(1 for e in host.replay(corr_d)
                 if e.get("event_type") == "execution_denied")
    assert denies == 1, f"a replayed denial must not re-run gates (× {denies})"

    # 3. A fresh id executes fresh (no accidental cross-id dedupe).
    f1 = _post_invoke({"capability_id": "conformance.echo",
                       "payload": {"value": "fresh"},
                       "invocation_id": f"inv-{RUN}-fresh-a"})
    f2 = _post_invoke({"capability_id": "conformance.echo",
                       "payload": {"value": "fresh"},
                       "invocation_id": f"inv-{RUN}-fresh-b"})
    assert "replayed" not in f1 and "replayed" not in f2, (
        "distinct invocation_ids must both execute fresh")


WIRE_CHECKS: list[tuple[str, Check]] = [
    ("capability declaration", check_declaration),
    ("capability discovery", check_discovery),
    ("invocation through envelope", check_invocation_envelope),
    ("correlation propagation", check_correlation_propagation),
    ("evidence emission on success", check_success_evidence),
    ("evidence emission on failure", check_failure_evidence),
    ("evidence emission on denial", check_denial_evidence),
    ("replay by correlation id", check_replay_by_correlation),
    ("standard denial codes", check_standard_denial_codes),
    ("approval-required governance (v0.2)", check_approval_required_governance),
    ("budget-exceeded governance (v0.2)", check_budget_exceeded_governance),
    ("risk-tier governance (v0.2)", check_risk_tier_governance),
    ("safety-guardrail governance (v0.2)", check_safety_governance),
    ("chain verification over /verify", check_wire_verify),
    ("identity document (v0.2 §3.1)", check_identity_document),
    ("export bundle verifies (v0.2 §4a)", check_export_bundle),
    ("capability-scoped caller key (binding §2)", check_scoped_caller_key),
    ("mandate gate (v0.2 §10)", check_mandate_gate),
    ("witness round-trip (v0.2 §12)", check_witness_roundtrip),
    ("mandate revocation (v0.2 §10, proposal 0007)", check_mandate_revocation),
    ("streaming invocation (binding, proposal 0006)", check_streaming_invocation),
    ("idempotent replay (v0.2 §13, proposal 0008)", check_idempotent_replay),
    ("sub-delegation (v0.2 §10, proposal 0009)", check_sub_delegation),
]

SUITES: dict[str, list[tuple[str, Check]]] = {
    "normative": NORMATIVE_CHECKS,
    "reference": REFERENCE_CHECKS,
    "wire": WIRE_CHECKS,
    "all": NORMATIVE_CHECKS + REFERENCE_CHECKS,
}

# Back-compat: existing callers importing CHECKS get the full run.
CHECKS: list[tuple[str, Check]] = SUITES["all"]


SAMPLE_HOSTS = {
    "passing": build_passing_host,
    "failing-no-evidence": lambda: BrokenNoEvidenceHost(),
    "failing-non-standard-codes": lambda: BrokenNonStandardCodesHost(),
    "failing-no-hash-chain": lambda: BrokenNoHashChainHost(),
}


async def _run_checks(host: Any, checks: list[tuple[str, Check]]) -> list[CheckResult]:
    results = []
    for name, check in checks:
        try:
            await check(host)
            results.append(CheckResult(name, True))
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(name, False, str(exc) or exc.__class__.__name__))
    return results


async def run(sample: str, suite: str = "all") -> list[CheckResult]:
    builder = SAMPLE_HOSTS.get(sample)
    if builder is None:
        raise ValueError(f"unknown sample host: {sample!r}. Choices: {list(SAMPLE_HOSTS)}")
    checks = SUITES.get(suite)
    if checks is None:
        raise ValueError(f"unknown suite: {suite!r}. Choices: {list(SUITES)}")
    host_or_coro = builder()
    host = await host_or_coro if hasattr(host_or_coro, "__await__") else host_or_coro
    return await _run_checks(host, checks)


# ─────────────────────────────────────────────────────────────────────────────
# Mesh suite (spec §11 + §10 Forwarding — routing-intermediary obligations)
#
# Topology: the RUNNER hosts two reference member hosts; the implementer's
# GATEWAY-UNDER-TEST routes between them; the runner drives the gateway
# black-box over HTTP and induces failure by killing its OWN member — the
# suite never needs control of the implementation. See MESH-FIXTURES.md.
#
# The checks are ORDERED and STATEFUL (destructive checks last; check 7 reads
# the correlation check 5 recorded) — NEVER reorder MESH_CHECKS.
# ─────────────────────────────────────────────────────────────────────────────


class MeshHarness:
    """The `host` argument for mesh checks: the gateway client + the runner's
    own member hosts/servers + cross-check state."""

    def __init__(self, gateway, members: dict) -> None:
        self.gateway = gateway            # RemoteCapabilityHost at the gateway
        self.members = members            # name -> {"host", "server", "url"}
        self.state: dict = {}             # cross-check state (ordered suite)

    def stop_member(self, name: str) -> None:
        entry = self.members[name]
        entry["server"].shutdown()
        entry["server"].server_close()
        entry["stopped"] = True


def _make_mesh_member(host_id: str, cap_ids: list[str]):
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))
    for cap_id in cap_ids:
        async def handler(_ctx, payload, _h=host_id):
            return {"served_by": _h, **(payload or {})}
        host.register(
            CapabilityDescriptor(id=cap_id, version="1.0.0",
                                 description=f"mesh fixture {cap_id}"),
            handler,
        )
    return host


def _serve_member(host, port: int):
    import threading

    from chp_core.http import create_http_server

    server = create_http_server(host, bind="127.0.0.1", port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _member_events(harness: "MeshHarness", correlation_id: str) -> list:
    """All events for a correlation across the runner's member hosts."""
    events = []
    for entry in harness.members.values():
        if not entry.get("stopped"):
            events.extend(entry["host"].replay(correlation_id))
    return events


def _gateway_get_json(h: "MeshHarness", path: str):
    """Raw authed GET against the gateway (routes the client doesn't wrap)."""
    import json as _json
    import urllib.request

    base = getattr(h.gateway, "_base", "")
    req = urllib.request.Request(f"{base}{path}", method="GET")
    api_key = getattr(h.gateway, "_api_key", None)
    if api_key:
        req.add_header("X-CHP-Key", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return _json.loads(resp.read().decode())


async def check_mesh_merged_discovery(h: "MeshHarness") -> None:
    """The gateway's /host merges every member's catalog and annotates owners."""
    descriptor = h.gateway.discover()  # RemoteCapabilityHost.discover is sync
    caps = {c.get("id"): c for c in descriptor.get("capabilities", [])}
    assert "mesh.echo" in caps and "mesh.only-a" in caps, (
        f"gateway catalog must merge both members; saw {sorted(k for k in caps)[:10]}")
    echo_hosts = caps["mesh.echo"].get("hosts") or []
    assert len(echo_hosts) == 2, f"mesh.echo is owned by BOTH members, got {echo_hosts}"


async def check_mesh_routed_invocation(h: "MeshHarness") -> None:
    """A routed invocation succeeds and its correlation lands in the member's
    evidence — the gateway propagated, not replaced, the correlation."""
    corr = f"{RUN}-mesh-routed"
    result = await invoke_host(h.gateway, "mesh.echo", {"value": "hi"},
                               correlation={"correlation_id": corr})
    assert result_value(result, "outcome") == "success", f"routed invoke failed: {result}"
    types = [e["event_type"] for e in _member_events(h, corr)]
    assert "execution_completed" in types, (
        "the member's evidence must carry the caller's correlation")


async def check_mesh_mandate_forwarded(h: "MeshHarness") -> None:
    """§10 Forwarding: a mandate presented AT THE GATEWAY is verified by the
    EXECUTING member — the delegate-under-principal subject lands in the
    member's chain even though the transport subject was rebound at the hop.
    The principal is a fresh key the members have never met (offline verify)."""
    import base64
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from chp_core import signing

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    key = signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                          public_key_b64=pub, _private=priv)
    now = datetime.now(timezone.utc)

    def _iso(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    mandate = signing.build_mandate(
        "mesh-principal", key, delegate_id="mesh-runner", scope=["mesh.echo"],
        valid_from=_iso(now - timedelta(minutes=1)),
        valid_until=_iso(now + timedelta(hours=1)), created_at=_iso(now))

    corr = f"{RUN}-mesh-mandated"
    result = await invoke_host(h.gateway, "mesh.echo", {"value": "delegated"},
                               correlation={"correlation_id": corr},
                               mandate=mandate)
    assert result_value(result, "outcome") == "success", f"mandated invoke failed: {result}"
    subjects = [e.get("subject") or {} for e in _member_events(h, corr)]
    bound = [s for s in subjects if s.get("type") == "mandate"]
    assert bound, "member evidence must carry the mandate-verified subject"
    assert bound[0].get("id") == "mesh-runner", f"delegate mismatch: {bound[0]}"
    assert bound[0].get("principal") == "mesh-principal", f"principal mismatch: {bound[0]}"


async def check_mesh_export_bundle(h: "MeshHarness") -> None:
    """/export on the gateway assembles the cross-host task bundle and it
    verifies as a unit (hash-chain tier — no member signing required).
    MUST run before the destructive checks (an unreachable member 503s)."""
    from chp_core.signing import verify_task_bundle

    corr = f"{RUN}-mesh-export"
    # Both members must contribute ≥1 event: A serves its sole capability,
    # B gets the co-owned one via affinity.
    a = await invoke_host(h.gateway, "mesh.only-a", {},
                          correlation={"correlation_id": corr})
    assert result_value(a, "outcome") == "success", f"mesh.only-a failed: {a}"
    b_url = h.members["member-b"]["url"]
    b = await invoke_host(h.gateway, "mesh.echo", {},
                          correlation={"correlation_id": corr},
                          metadata={"prefer": b_url})
    assert result_value(b, "outcome") == "success", f"prefer-B invoke failed: {b}"

    task = _gateway_get_json(h, f"/export/{corr}")
    assert task.get("kind") == "task-bundle", f"expected a task bundle, got {task.get('kind')}"
    tv = verify_task_bundle(task)
    assert tv.valid, f"assembled task bundle must verify: {tv.reason}"
    host_ids = {b_.get("host_id") for b_ in task.get("bundles", [])}
    assert host_ids == {"mesh-member-a", "mesh-member-b"}, (
        f"both members must contribute: {host_ids}")
    h.state["export_corr"] = corr


async def check_mesh_failover(h: "MeshHarness") -> None:
    """DESTRUCTIVE: member A dies; the co-owned capability fails over to B."""
    h.stop_member("member-a")
    corr = f"{RUN}-mesh-down"
    h.state["down_corr"] = corr
    result = await invoke_host(h.gateway, "mesh.echo", {},
                               correlation={"correlation_id": corr})
    assert result_value(result, "outcome") == "success", (
        f"co-owned capability must fail over: {result}")
    data = result_value(result, "data") or {}
    assert data.get("served_by") == "mesh-member-b", f"expected member B, got {data}"


async def check_mesh_host_unreachable(h: "MeshHarness") -> None:
    """The solely-owned capability is now unplaceable: a PROCESSED denial —
    HTTP 200, reserved host_unreachable, retryable, attempted hosts named."""
    result = await invoke_host(h.gateway, "mesh.only-a", {},
                               correlation={"correlation_id": h.state["down_corr"]})
    assert result_value(result, "outcome") == "denied", (
        f"must be a PROCESSED denial (HTTP 200 + outcome denied), got: {result}")
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "host_unreachable", f"reserved code required, got {code!r}"
    retryable = (denial.get("retryable") if isinstance(denial, dict)
                 else getattr(denial, "retryable", None))
    assert retryable is True, "host_unreachable is retryable advice"
    details = (denial.get("details") if isinstance(denial, dict)
               else getattr(denial, "details", None)) or {}
    assert details.get("attempted_hosts"), "details must name the attempted hosts"


async def check_mesh_replay_disclosure(h: "MeshHarness") -> None:
    """/replay is never silently partial: partial=true + missing_hosts, and the
    gateway's own chain (the failover transition) merges into the timeline
    (MESH-FIXTURES requires gateway.store)."""
    corr = h.state["down_corr"]
    result = h.gateway.replay_result(corr)
    data = result if isinstance(result, dict) else result.to_dict()
    assert data.get("partial") is True, f"partial replay must be disclosed, got {data.get('partial')}"
    assert data.get("missing_hosts"), "missing_hosts must name the unreachable member"
    types = [e.get("event_type") for e in data.get("events", [])]
    assert "host_marked_unhealthy" in types, (
        "the gateway's own §11 transition must merge into the stitched replay")


async def check_mesh_export_refuses_partial(h: "MeshHarness") -> None:
    """/export with a member down is a clean 503 — a silently-partial evidence
    bundle is the failure task bundles exist to prevent."""
    import urllib.error

    try:
        _gateway_get_json(h, f"/export/{h.state['export_corr']}")
    except urllib.error.HTTPError as exc:
        assert exc.code == 503, f"expected 503 on partial export, got {exc.code}"
        return
    raise AssertionError("partial /export must refuse with 503, not return a bundle")


MESH_CHECKS: list[tuple[str, Check]] = [
    # ORDERED + STATEFUL — never reorder (destructive checks last; later
    # checks read state earlier checks recorded).
    ("merged discovery across members", check_mesh_merged_discovery),
    ("routed invocation propagates correlation", check_mesh_routed_invocation),
    ("mandate forwarded unchanged (§10 Forwarding)", check_mesh_mandate_forwarded),
    ("export assembles a verifying task bundle", check_mesh_export_bundle),
    ("failover to the surviving owner", check_mesh_failover),
    ("host_unreachable is a processed denial (§11)", check_mesh_host_unreachable),
    ("partial replay disclosed + gateway chain merged", check_mesh_replay_disclosure),
    ("export refuses partial with 503", check_mesh_export_refuses_partial),
]


SUITES["mesh"] = MESH_CHECKS  # driven via --gateway-url (never --url)


async def run_mesh(gateway_url: str, *, api_key: str | None = None,
                   member_ports: tuple[int, int] = (8951, 8952),
                   after_members=None, gateway_timeout: float = 60.0) -> list[CheckResult]:
    """The mesh suite: spawn the runner's two member hosts, wait for the
    implementer's gateway to route them, drive the ordered checks, tear down.

    `after_members(urls)` fires once the members are listening — the self-test
    uses it to launch the reference gateway subprocess."""
    import time as _time

    from chp_core.http import RemoteCapabilityHost

    # The runner's members are ALWAYS keyless (the gateway manifest carries no
    # api_key_env) — ambient auth env in the runner process would 401 the
    # gateway at the members, so it is cleared before they start (and before
    # any after_members subprocess inherits the environment).
    os.environ.pop("CHP_HOST_API_KEY", None)
    os.environ.pop("CHP_HOST_API_KEYS", None)

    members = {
        "member-a": {"host": _make_mesh_member("mesh-member-a", ["mesh.echo", "mesh.only-a"])},
        "member-b": {"host": _make_mesh_member("mesh-member-b", ["mesh.echo"])},
    }
    try:
        for (name, entry), port in zip(members.items(), member_ports):
            server = _serve_member(entry["host"], port)
            entry["server"] = server
            entry["url"] = f"http://127.0.0.1:{server.server_address[1]}"

        if after_members is not None:
            after_members({n: e["url"] for n, e in members.items()})

        gateway = RemoteCapabilityHost(gateway_url, api_key=api_key)
        harness = MeshHarness(gateway, members)

        # Wait until the gateway has ROUTED the members (it discovers its
        # routing table at boot — members-first start order is a MUST).
        deadline = _time.monotonic() + gateway_timeout
        while True:
            try:
                descriptor = gateway.discover()  # sync client method
                ids = {c.get("id") for c in descriptor.get("capabilities", [])}
                if "mesh.only-a" in ids:
                    break
            except Exception:
                pass
            if _time.monotonic() > deadline:
                raise TimeoutError(
                    f"gateway at {gateway_url} never routed the runner's members "
                    f"({[e['url'] for e in members.values()]}). Start ORDER matters: "
                    "the members must be listening BEFORE the gateway boots "
                    "(it discovers its routing table at connect) — see MESH-FIXTURES.md.")
            _time.sleep(0.25)

        return await _run_checks(harness, MESH_CHECKS)
    finally:
        for entry in members.values():
            if not entry.get("stopped") and entry.get("server"):
                entry["server"].shutdown()
                entry["server"].server_close()


async def run_url(base_url: str, *, api_key: str | None = None,
                  suite: str = "wire") -> list[CheckResult]:
    """Black-box: drive a running host over HTTP through RemoteCapabilityHost."""
    from chp_core.http import RemoteCapabilityHost

    checks = SUITES.get(suite)
    if checks is None:
        raise ValueError(f"unknown suite: {suite!r}. Choices: {list(SUITES)}")
    host = RemoteCapabilityHost(base_url, api_key=api_key)
    return await _run_checks(host, checks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CHP v0.1 conformance checks.")
    parser.add_argument(
        "--sample",
        choices=list(SAMPLE_HOSTS),
        default="passing",
        help="Built-in sample host to test against.",
    )
    parser.add_argument(
        "--suite",
        choices=list(SUITES),
        default="all",
        help="normative = spec MUSTs (defines conformance); reference = bundled "
             "capability library; wire = black-box HTTP checks (--url); all = "
             "normative + reference (default).",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Black-box: base URL of a running host to test over HTTP "
             "(spec/chp-http-binding.md). Defaults --suite to 'wire'.",
    )
    parser.add_argument(
        "--key",
        default=os.environ.get("CHP_HOST_API_KEY"),
        help="X-CHP-Key for the black-box host (or set CHP_HOST_API_KEY).",
    )
    parser.add_argument(
        "--gateway-url",
        default=None,
        dest="gateway_url",
        help="Mesh suite: base URL of a running ROUTING GATEWAY under test. The "
             "runner hosts two reference member hosts (--member-ports) the "
             "gateway must be configured to route — see conformance/MESH-FIXTURES.md.",
    )
    parser.add_argument(
        "--member-ports",
        default="8951,8952",
        dest="member_ports",
        help="Mesh suite: the two localhost ports the runner's member hosts bind.",
    )
    args = parser.parse_args()

    if args.gateway_url:
        ports = tuple(int(p) for p in args.member_ports.split(","))
        results = asyncio.run(run_mesh(args.gateway_url, api_key=args.key,
                                       member_ports=ports))
    elif args.url:
        suite = args.suite if args.suite != "all" else "wire"
        results = asyncio.run(run_url(args.url, api_key=args.key, suite=suite))
    else:
        if args.suite == "mesh":
            print("--suite mesh needs --gateway-url (see conformance/MESH-FIXTURES.md)",
                  file=sys.stderr)
            return 2
        results = asyncio.run(run(args.sample, args.suite))
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        suffix = f" - {result.detail}" if result.detail else ""
        print(f"{status} {result.name}{suffix}")

    if args.gateway_url:
        print(f"\n[mesh] {sum(r.ok for r in results)}/{len(results)} routing-intermediary "
              f"checks against {args.gateway_url}")
    elif args.url:
        print(f"\n[wire] {sum(r.ok for r in results)}/{len(results)} black-box HTTP checks "
              f"against {args.url}")
    if args.suite == "normative":
        print(f"\n[normative] {sum(r.ok for r in results)}/{len(results)} spec MUST checks "
              "— this is what spec-conformance means (reference library not required).")
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
