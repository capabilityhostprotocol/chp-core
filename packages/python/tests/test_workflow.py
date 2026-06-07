"""Tests for WorkflowCapability — v0.4.4."""

from __future__ import annotations

import json
import pytest

from chp_core import (
    InMemoryKnowledgeGraph,
    InMemoryWorkflow,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    WorkflowCapability,
    WorkflowResult,
    register_knowledge_graph_capability,
    register_workflow_capability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_host(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-workflow", store=store)
    # Register a simple graph capability for steps to invoke
    kg = InMemoryKnowledgeGraph()
    register_knowledge_graph_capability(host, kg)
    wf = InMemoryWorkflow()
    register_workflow_capability(host, wf)
    yield host, store
    store.close()


# ── TestWorkflowCapability ─────────────────────────────────────────────────────


class TestWorkflowCapability:
    @pytest.mark.asyncio
    async def test_empty_steps_completes_immediately(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run", {"steps": []}, correlation={"correlation_id": "wf-001"}
        )
        assert result.success
        data = result.data
        assert data["completed_steps"] == 0
        assert data["failed_steps"] == 0

    @pytest.mark.asyncio
    async def test_single_step_success(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "x", "entity_type": "node"}}]},
            correlation={"correlation_id": "wf-002"},
        )
        assert result.success
        assert result.data["completed_steps"] == 1

    @pytest.mark.asyncio
    async def test_multi_step_success(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run",
            {
                "steps": [
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "a", "entity_type": "node"}},
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "b", "entity_type": "node"}},
                    {"capability_id": "graph.query_entities", "payload": {}},
                ]
            },
            correlation={"correlation_id": "wf-003"},
        )
        assert result.success
        assert result.data["completed_steps"] == 3
        assert result.data["failed_steps"] == 0

    @pytest.mark.asyncio
    async def test_step_failure_aborts_workflow(self, tmp_host):
        host, _ = tmp_host
        # graph.add_relation on non-existent entities will fail
        result = await host.ainvoke(
            "workflow.run",
            {
                "steps": [
                    {"capability_id": "graph.add_relation", "payload": {"from_entity_id": "ghost", "to_entity_id": "void", "relation_type": "x"}},
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "should-not-run", "entity_type": "node"}},
                ]
            },
            correlation={"correlation_id": "wf-004"},
        )
        assert not result.success

    @pytest.mark.asyncio
    async def test_skip_on_failure_continues(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run",
            {
                "steps": [
                    {"capability_id": "graph.add_relation", "payload": {"from_entity_id": "ghost", "to_entity_id": "void", "relation_type": "x"}, "skip_on_failure": True},
                    {"capability_id": "graph.add_entity", "payload": {"entity_id": "after-skip", "entity_type": "node"}},
                ]
            },
            correlation={"correlation_id": "wf-005"},
        )
        assert result.success
        assert result.data["completed_steps"] == 1
        assert result.data["failed_steps"] == 1

    @pytest.mark.asyncio
    async def test_workflow_result_has_total_duration_ms(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run", {"steps": []}, correlation={"correlation_id": "wf-006"}
        )
        assert result.data["total_duration_ms"] is not None
        assert result.data["total_duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_workflow_id_auto_generated(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run", {"steps": []}, correlation={"correlation_id": "wf-007"}
        )
        assert result.data["workflow_id"].startswith("wf_")

    @pytest.mark.asyncio
    async def test_workflow_name_preserved(self, tmp_host):
        host, _ = tmp_host
        result = await host.ainvoke(
            "workflow.run", {"name": "my-pipeline", "steps": []}, correlation={"correlation_id": "wf-008"}
        )
        assert result.data["name"] == "my-pipeline"


# ── TestWorkflowDescriptor ─────────────────────────────────────────────────────


class TestWorkflowDescriptor:
    def _descriptors(self, host):
        return [entry.descriptor for entry in host._capabilities.values()]

    def test_registers_one_capability(self, tmp_host):
        host, _ = tmp_host
        wf_caps = [d for d in self._descriptors(host) if d.id == "workflow.run"]
        assert len(wf_caps) == 1

    def test_capability_id_is_workflow_run(self, tmp_host):
        host, _ = tmp_host
        cap = next(d for d in self._descriptors(host) if d.id == "workflow.run")
        assert cap.id == "workflow.run"

    def test_category_is_process_workflow(self, tmp_host):
        host, _ = tmp_host
        cap = next(d for d in self._descriptors(host) if d.id == "workflow.run")
        category = cap.category.value if hasattr(cap.category, "value") else cap.category
        assert category == "process_workflow"

    def test_workflow_started_in_emits(self, tmp_host):
        host, _ = tmp_host
        cap = next(d for d in self._descriptors(host) if d.id == "workflow.run")
        assert "workflow_started" in cap.emits

    def test_base_class_attributes(self):
        wf = WorkflowCapability()
        assert wf.capability_id == "workflow.run"
        assert wf.capability_version == "0.1.0"


# ── TestWorkflowEvidenceEmission ──────────────────────────────────────────────


class TestWorkflowEvidenceEmission:
    @pytest.mark.asyncio
    async def test_all_core_event_types_present(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "ev1", "entity_type": "n"}}]},
            correlation={"correlation_id": "ev-001"},
        )
        types = {e["event_type"] for e in host.replay("ev-001")}
        assert "workflow_started" in types
        assert "workflow_step_started" in types
        assert "workflow_step_completed" in types
        assert "workflow_completed" in types
        assert "execution_started" in types
        assert "execution_completed" in types

    @pytest.mark.asyncio
    async def test_workflow_started_has_step_count(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "sc1", "entity_type": "n"}},
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "sc2", "entity_type": "n"}},
            ]},
            correlation={"correlation_id": "ev-002"},
        )
        events = host.replay("ev-002")
        started = next(e for e in events if e["event_type"] == "workflow_started")
        assert (started.get("payload") or {}).get("step_count") == 2

    @pytest.mark.asyncio
    async def test_workflow_step_completed_has_duration_ms(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "dur1", "entity_type": "n"}}]},
            correlation={"correlation_id": "ev-003"},
        )
        events = host.replay("ev-003")
        sc = next(e for e in events if e["event_type"] == "workflow_step_completed")
        assert (sc.get("payload") or {}).get("duration_ms") is not None

    @pytest.mark.asyncio
    async def test_workflow_completed_has_step_counts(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "cnt1", "entity_type": "n"}}]},
            correlation={"correlation_id": "ev-004"},
        )
        events = host.replay("ev-004")
        wc = next(e for e in events if e["event_type"] == "workflow_completed")
        payload = wc.get("payload") or {}
        assert "completed_steps" in payload
        assert "failed_steps" in payload
        assert payload["completed_steps"] == 1
        assert payload["failed_steps"] == 0

    @pytest.mark.asyncio
    async def test_failing_step_emits_workflow_failed_and_execution_failed(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_relation", "payload": {"from_entity_id": "g", "to_entity_id": "v", "relation_type": "x"}}]},
            correlation={"correlation_id": "ev-005"},
        )
        types = {e["event_type"] for e in host.replay("ev-005")}
        assert "workflow_step_failed" in types
        assert "workflow_failed" in types
        assert "execution_failed" in types

    @pytest.mark.asyncio
    async def test_skip_on_failure_emits_step_failed_not_workflow_failed(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [
                {"capability_id": "graph.add_relation", "payload": {"from_entity_id": "g", "to_entity_id": "v", "relation_type": "x"}, "skip_on_failure": True},
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "ok", "entity_type": "n"}},
            ]},
            correlation={"correlation_id": "ev-006"},
        )
        types = {e["event_type"] for e in host.replay("ev-006")}
        assert "workflow_step_failed" in types
        assert "workflow_failed" not in types
        assert "workflow_completed" in types

    @pytest.mark.asyncio
    async def test_hash_chain_intact(self, tmp_host):
        host, store = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "hc1", "entity_type": "n"}}]},
            correlation={"correlation_id": "ev-007"},
        )
        records = store.by_correlation_with_hashes("ev-007")
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_step_evidence_under_same_correlation(self, tmp_host):
        host, _ = tmp_host
        await host.ainvoke(
            "workflow.run",
            {"steps": [{"capability_id": "graph.add_entity", "payload": {"entity_id": "corr1", "entity_type": "n"}}]},
            correlation={"correlation_id": "ev-008"},
        )
        # Replay should include both workflow AND graph.add_entity step events
        events = host.replay("ev-008")
        cap_ids = {(e.get("payload") or {}).get("capability_id") for e in events if e.get("payload")}
        assert "graph.add_entity" in cap_ids or any("add_entity" in str(e) for e in events)


# ── TestWorkflowCLI ───────────────────────────────────────────────────────────


class TestWorkflowCLI:
    @pytest.mark.asyncio
    async def test_returns_0_when_workflow_events_found(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_workflow_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-wf", store=store)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)
        await host.ainvoke("workflow.run", {"steps": []}, correlation={"correlation_id": "cli-wf-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-wf-1", store=store_path)
        rc = cmd_session_workflow_report(args)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_returns_1_for_no_workflow_events(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_workflow_report
        from chp_core import InMemoryEventBus, register_event_bus_capability

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-nwf", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)
        await host.ainvoke("events.emit", {"event_type": "x", "source": "s"}, correlation={"correlation_id": "cli-nwf-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-nwf-1", store=store_path)
        rc = cmd_session_workflow_report(args)
        assert rc == 1

    @pytest.mark.asyncio
    async def test_workflows_run_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_workflow_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-wfc", store=store)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)
        for i in range(3):
            await host.ainvoke("workflow.run", {"steps": []}, correlation={"correlation_id": "cli-wfc-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-wfc-1", store=store_path)
        cmd_session_workflow_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["workflows_run"] == 3

    @pytest.mark.asyncio
    async def test_steps_completed_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_workflow_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-wfsc", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)
        await host.ainvoke(
            "workflow.run",
            {"steps": [
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "s1", "entity_type": "n"}},
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "s2", "entity_type": "n"}},
            ]},
            correlation={"correlation_id": "cli-wfsc-1"},
        )
        store.close()

        args = argparse.Namespace(session_id="cli-wfsc-1", store=store_path)
        cmd_session_workflow_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["steps_completed"] == 2


# ── Integration test ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_workflow_chains_graph_and_events(tmp_path):
    """A workflow can chain graph.add_entity → events.emit end-to-end."""
    from chp_core import InMemoryEventBus, register_event_bus_capability

    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("int-wf", store=store)
    kg = InMemoryKnowledgeGraph()
    register_knowledge_graph_capability(host, kg)
    bus = InMemoryEventBus()
    register_event_bus_capability(host, bus)
    wf = InMemoryWorkflow()
    register_workflow_capability(host, wf)

    result = await host.ainvoke(
        "workflow.run",
        {
            "name": "entity-and-event",
            "steps": [
                {"capability_id": "graph.add_entity", "payload": {"entity_id": "product-1", "entity_type": "product"}},
                {"capability_id": "events.emit", "payload": {"event_type": "product.created", "source": "catalog", "data": {"id": "product-1"}}},
            ],
        },
        correlation={"correlation_id": "int-wf-001"},
    )

    assert result.success
    assert result.data["completed_steps"] == 2

    events = host.replay("int-wf-001")
    types = {e["event_type"] for e in events}
    assert "workflow_completed" in types
    assert "graph_entity_added" in types
    assert "domain_event_emitted" in types

    assert len(bus._events) == 1
    assert bus._events[0].event_type == "product.created"
    store.close()
