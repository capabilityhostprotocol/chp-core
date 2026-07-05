#!/usr/bin/env python3
"""Minimal CHP v0.1 conformance runner."""

from __future__ import annotations

import argparse
import asyncio
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


async def check_standard_denial_codes(host: Any) -> None:
    """Invoking a missing capability produces the standard denial code 'capability_not_found'."""
    corr_id = "conf-denial-codes-001"
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
        host = LocalCapabilityHost("conf-schema", store=store)

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
            correlation={"correlation_id": "conf-schema-bad"},
        )
        assert not bad.success, "expected denial for invalid payload"
        assert bad.outcome == "denied", f"expected denied, got {bad.outcome!r}"
        assert bad.denial.code == "input_schema_validation_failed", (
            f"expected 'input_schema_validation_failed', got {bad.denial.code!r}"
        )

        good = await host.ainvoke(
            "conf.typed",
            {"n": 42},
            correlation={"correlation_id": "conf-schema-good"},
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
    corr_id = "conf-chain-001"

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
            ref_host = LocalCapabilityHost("conf-chain", store=store)

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
        host = LocalCapabilityHost("conf-sign", store=store)

        async def echo(_ctx, payload):
            return {"echo": payload.get("value")}

        host.register(CapabilityDescriptor(id="conf.sign.echo", version="1.0.0", description=""), echo)
        await host.ainvoke("conf.sign.echo", {"value": "v"}, correlation={"correlation_id": "cs"})

        key = signing.generate_keypair(os.path.join(d, "keys"))
        events = store.export_correlation("cs")
        bundle = signing.sign_bundle(signing.build_bundle("conf-sign", events, created_at="2026-01-01T00:00:00Z"), key)
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
        host = LocalCapabilityHost("conf-ret", store=store)

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
        host, "conformance.approval", {}, correlation={"correlation_id": "conf-approval-001"}
    )
    assert not result_value(result, "success"), f"approval-gated must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "approval_required", f"expected 'approval_required', got {code!r}"
    types = [e["event_type"] for e in host.replay("conf-approval-001")]
    assert "approval_requested" in types, f"approval_requested not emitted: {types}"
    assert "execution_started" not in types, "gated capability must not begin execution"


async def check_budget_exceeded_governance(host: Any) -> None:
    """v0.2 governance (§4.1): once an autonomy action_limit is exhausted, further
    invocations on that correlation are denied with the reserved code
    'budget_exceeded' and a 'budget_exceeded' event — the autonomy-budget
    differentiator. The invocation before the limit still succeeds. Uses the
    fixture profile's conformance.budgeted (action_limit=1)."""
    corr = {"correlation_id": "conf-budget-001"}
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
    types = [e["event_type"] for e in host.replay("conf-budget-001")]
    assert "budget_exceeded" in types, f"budget_exceeded event not emitted: {types}"


async def check_risk_tier_governance(host: Any) -> None:
    """v0.2 governance (chp-governance-v0.2.md §3): a capability whose risk tier
    orders above the host's max_risk_tier is denied with the reserved code
    'policy_blocked'. The risk-tier differentiator — guarded. Uses the fixture
    profile's conformance.risky ('high') against a host capped at 'medium'."""
    result = await invoke_host(
        host, "conformance.risky", {}, correlation={"correlation_id": "conf-risk-001"}
    )
    assert not result_value(result, "success"), f"over-tier capability must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "policy_blocked", f"expected 'policy_blocked', got {code!r}"
    types = [e["event_type"] for e in host.replay("conf-risk-001")]
    assert "execution_started" not in types, "over-tier capability must not begin execution"


async def check_safety_governance(host: Any) -> None:
    """v0.2 governance (chp-governance-v0.2.md §4.2): with a safety evaluator
    configured, an invocation a guardrail blocks is denied with the reserved
    'safety_blocked' code, records the assessment pair (started/completed) and
    safety_action_blocked, and never starts execution. The safety differentiator
    — a signed safety verdict on the governed plane, guarded. Uses the fixture
    profile's conformance.unsafe."""
    result = await invoke_host(
        host, "conformance.unsafe", {}, correlation={"correlation_id": "conf-safety-001"}
    )
    assert not result_value(result, "success"), f"guardrail-blocked must be denied: {result}"
    assert result_value(result, "outcome") == "denied", (
        f"expected 'denied', got {result_value(result, 'outcome')!r}"
    )
    denial = result_value(result, "denial")
    code = denial.get("code") if isinstance(denial, dict) else getattr(denial, "code", None)
    assert code == "safety_blocked", f"expected 'safety_blocked', got {code!r}"
    types = [e["event_type"] for e in host.replay("conf-safety-001")]
    for required in ("safety_assessment_started", "safety_assessment_completed",
                     "safety_action_blocked"):
        assert required in types, f"missing {required}: {types}"
    assert "execution_started" not in types, "blocked capability must not begin execution"


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
    corr = "conf-wire-verify"
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
    args = parser.parse_args()

    if args.url:
        suite = args.suite if args.suite != "all" else "wire"
        results = asyncio.run(run_url(args.url, api_key=args.key, suite=suite))
    else:
        results = asyncio.run(run(args.sample, args.suite))
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        suffix = f" - {result.detail}" if result.detail else ""
        print(f"{status} {result.name}{suffix}")

    if args.url:
        print(f"\n[wire] {sum(r.ok for r in results)}/{len(results)} black-box HTTP checks "
              f"against {args.url}")
    if args.suite == "normative":
        print(f"\n[normative] {sum(r.ok for r in results)}/{len(results)} spec MUST checks "
              "— this is what spec-conformance means (reference library not required).")
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
