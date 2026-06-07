"""Tests for KnowledgeGraphCapability — v0.4.3."""

from __future__ import annotations

import json
import pytest

from chp_core import (
    EntityRecord,
    GraphQueryResult,
    InMemoryKnowledgeGraph,
    KnowledgeGraphCapability,
    LocalCapabilityHost,
    RelationRecord,
    SQLiteEvidenceStore,
    register_knowledge_graph_capability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def kg():
    return InMemoryKnowledgeGraph()


@pytest.fixture
def tmp_host_and_kg(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-graph", store=store)
    kg = InMemoryKnowledgeGraph()
    register_knowledge_graph_capability(host, kg)
    yield host, kg, store
    store.close()


# ── TestInMemoryKnowledgeGraph ─────────────────────────────────────────────────


class TestInMemoryKnowledgeGraph:
    def test_add_entity_returns_entity_record(self, kg):
        r = kg.add_entity("e1", "person", label="Alice")
        assert isinstance(r, EntityRecord)
        assert r.entity_id == "e1"
        assert r.entity_type == "person"
        assert r.label == "Alice"

    def test_add_entity_no_label(self, kg):
        r = kg.add_entity("e2", "doc")
        assert r.label is None

    def test_add_entity_with_properties(self, kg):
        r = kg.add_entity("e3", "org", properties={"size": "large"})
        assert r.properties == {"size": "large"}

    def test_add_entity_upserts_same_id(self, kg):
        kg.add_entity("e1", "person", label="Alice")
        kg.add_entity("e1", "person", label="Alicia")
        result = kg.query_entities()
        assert result.entity_count == 1
        assert result.entities[0].label == "Alicia"

    def test_add_relation_returns_relation_record(self, kg):
        kg.add_entity("a", "person")
        kg.add_entity("b", "person")
        r = kg.add_relation("a", "b", "knows")
        assert isinstance(r, RelationRecord)
        assert r.from_entity_id == "a"
        assert r.to_entity_id == "b"
        assert r.relation_type == "knows"

    def test_add_relation_raises_for_unknown_from_id(self, kg):
        kg.add_entity("b", "person")
        with pytest.raises(ValueError, match="entity not found"):
            kg.add_relation("missing", "b", "knows")

    def test_add_relation_raises_for_unknown_to_id(self, kg):
        kg.add_entity("a", "person")
        with pytest.raises(ValueError, match="entity not found"):
            kg.add_relation("a", "missing", "knows")

    def test_query_entities_returns_all(self, kg):
        kg.add_entity("e1", "person")
        kg.add_entity("e2", "org")
        result = kg.query_entities()
        assert isinstance(result, GraphQueryResult)
        assert result.entity_count == 2

    def test_query_entities_filters_by_type(self, kg):
        kg.add_entity("p1", "person")
        kg.add_entity("d1", "doc")
        result = kg.query_entities(entity_type="person")
        assert result.entity_count == 1
        assert result.entities[0].entity_type == "person"

    def test_query_entities_respects_limit(self, kg):
        for i in range(5):
            kg.add_entity(f"e{i}", "person")
        result = kg.query_entities(limit=3)
        assert result.entity_count == 3

    def test_traverse_returns_connected_at_depth_1(self, kg):
        kg.add_entity("a", "person")
        kg.add_entity("b", "person")
        kg.add_entity("c", "person")
        kg.add_relation("a", "b", "knows")
        kg.add_relation("a", "c", "knows")
        result = kg.traverse("a", depth=1)
        ids = {e.entity_id for e in result.entities}
        assert ids == {"b", "c"}

    def test_traverse_excludes_start_id(self, kg):
        kg.add_entity("a", "person")
        kg.add_entity("b", "person")
        kg.add_relation("a", "b", "knows")
        result = kg.traverse("a")
        assert all(e.entity_id != "a" for e in result.entities)

    def test_traverse_respects_incoming_direction(self, kg):
        kg.add_entity("a", "person")
        kg.add_entity("b", "person")
        kg.add_relation("a", "b", "knows")
        result = kg.traverse("b", direction="incoming")
        ids = {e.entity_id for e in result.entities}
        assert "a" in ids

    def test_traverse_query_type_is_traverse(self, kg):
        kg.add_entity("x", "node")
        result = kg.traverse("x")
        assert result.query_type == "traverse"

    def test_query_result_has_latency_ms(self, kg):
        result = kg.query_entities()
        assert result.latency_ms is not None
        assert result.latency_ms >= 0


# ── TestKnowledgeGraphDescriptor ──────────────────────────────────────────────


class TestKnowledgeGraphDescriptor:
    def _descriptors(self, host):
        return [entry.descriptor for entry in host._capabilities.values()]

    def test_registers_four_capability_ids(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        ids = {d.id for d in self._descriptors(host)}
        assert "graph.add_entity" in ids
        assert "graph.add_relation" in ids
        assert "graph.query_entities" in ids
        assert "graph.traverse" in ids

    def test_all_ids_start_with_graph(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        graph_ids = [d.id for d in self._descriptors(host) if d.id.startswith("graph.")]
        assert len(graph_ids) == 4

    def test_add_entity_emits_includes_graph_entity_added(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        cap = next(d for d in self._descriptors(host) if d.id == "graph.add_entity")
        assert "graph_entity_added" in cap.emits

    def test_all_caps_category_data_knowledge(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        graph_caps = [d for d in self._descriptors(host) if d.id.startswith("graph.")]
        for cap in graph_caps:
            category = cap.category.value if hasattr(cap.category, "value") else cap.category
            assert category == "data_knowledge", f"{cap.id} has wrong category"

    def test_base_class_raises_not_implemented(self):
        base = KnowledgeGraphCapability()
        with pytest.raises(NotImplementedError):
            base.add_entity("x", "y")
        with pytest.raises(NotImplementedError):
            base.add_relation("x", "y", "z")
        with pytest.raises(NotImplementedError):
            base.query_entities()
        with pytest.raises(NotImplementedError):
            base.traverse("x")


# ── TestKnowledgeGraphEvidenceEmission ────────────────────────────────────────


class TestKnowledgeGraphEvidenceEmission:
    @pytest.mark.asyncio
    async def test_add_entity_emits_graph_entity_added(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        await host.ainvoke("graph.add_entity", {"entity_id": "e1", "entity_type": "person"},
                           correlation={"correlation_id": "ev-001"})
        types = {e["event_type"] for e in host.replay("ev-001")}
        assert "graph_entity_added" in types

    @pytest.mark.asyncio
    async def test_add_relation_emits_graph_relation_added(self, tmp_host_and_kg):
        host, kg, store = tmp_host_and_kg
        await host.ainvoke("graph.add_entity", {"entity_id": "a", "entity_type": "p"},
                           correlation={"correlation_id": "ev-002"})
        await host.ainvoke("graph.add_entity", {"entity_id": "b", "entity_type": "p"},
                           correlation={"correlation_id": "ev-002"})
        await host.ainvoke("graph.add_relation",
                           {"from_entity_id": "a", "to_entity_id": "b", "relation_type": "knows"},
                           correlation={"correlation_id": "ev-002"})
        types = {e["event_type"] for e in host.replay("ev-002")}
        assert "graph_relation_added" in types

    @pytest.mark.asyncio
    async def test_query_entities_emits_graph_queried(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        await host.ainvoke("graph.query_entities", {}, correlation={"correlation_id": "ev-003"})
        types = {e["event_type"] for e in host.replay("ev-003")}
        assert "graph_queried" in types

    @pytest.mark.asyncio
    async def test_traverse_emits_graph_traversed(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        kg.add_entity("s", "node")
        await host.ainvoke("graph.traverse", {"start_id": "s"},
                           correlation={"correlation_id": "ev-004"})
        types = {e["event_type"] for e in host.replay("ev-004")}
        assert "graph_traversed" in types

    @pytest.mark.asyncio
    async def test_graph_entity_added_payload_has_entity_id_and_type(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        await host.ainvoke("graph.add_entity",
                           {"entity_id": "x1", "entity_type": "widget", "label": "Foo"},
                           correlation={"correlation_id": "ev-005"})
        events = host.replay("ev-005")
        added = next(e for e in events if e["event_type"] == "graph_entity_added")
        payload = added.get("payload") or {}
        assert payload["entity_id"] == "x1"
        assert payload["entity_type"] == "widget"
        assert payload["label"] == "Foo"

    @pytest.mark.asyncio
    async def test_graph_queried_payload_no_entity_list(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        kg.add_entity("e1", "node")
        await host.ainvoke("graph.query_entities", {"entity_type": "node"},
                           correlation={"correlation_id": "ev-006"})
        events = host.replay("ev-006")
        queried = next(e for e in events if e["event_type"] == "graph_queried")
        payload = queried.get("payload") or {}
        assert "entity_count" in payload
        assert "entities" not in payload

    @pytest.mark.asyncio
    async def test_hash_chain_intact(self, tmp_host_and_kg):
        host, kg, store = tmp_host_and_kg
        await host.ainvoke("graph.add_entity", {"entity_id": "h1", "entity_type": "node"},
                           correlation={"correlation_id": "ev-007"})
        records = store.by_correlation_with_hashes("ev-007")
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_failed_add_relation_emits_graph_operation_failed(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        result = await host.ainvoke(
            "graph.add_relation",
            {"from_entity_id": "ghost", "to_entity_id": "void", "relation_type": "x"},
            correlation={"correlation_id": "ev-008"},
        )
        assert not result.success
        events = host.replay("ev-008")
        types = {e["event_type"] for e in events}
        assert "graph_operation_failed" in types
        assert "execution_failed" in types

    @pytest.mark.asyncio
    async def test_execution_started_and_completed_present(self, tmp_host_and_kg):
        host, kg, _ = tmp_host_and_kg
        await host.ainvoke("graph.add_entity", {"entity_id": "sc", "entity_type": "node"},
                           correlation={"correlation_id": "ev-009"})
        types = {e["event_type"] for e in host.replay("ev-009")}
        assert "execution_started" in types
        assert "execution_completed" in types


# ── TestGraphReportCLI ────────────────────────────────────────────────────────


class TestGraphReportCLI:
    @pytest.mark.asyncio
    async def test_returns_0_when_graph_events_found(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_graph_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-graph", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        await host.ainvoke("graph.add_entity", {"entity_id": "c1", "entity_type": "node"},
                           correlation={"correlation_id": "cli-sess-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-sess-1", store=store_path)
        rc = cmd_session_graph_report(args)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_returns_1_for_session_with_no_graph_events(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_graph_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-nograph", store=store)
        # Invoke a non-graph capability just to create a session
        from chp_core import InMemoryKeywordRetrievalCapability, register_retrieval_capability
        rcap = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, rcap)
        await host.ainvoke("retrieval.retrieve", {"query": "x"},
                           correlation={"correlation_id": "cli-sess-ng"})
        store.close()

        args = argparse.Namespace(session_id="cli-sess-ng", store=store_path)
        rc = cmd_session_graph_report(args)
        assert rc == 1

    @pytest.mark.asyncio
    async def test_entities_added_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_graph_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-count", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        for i in range(3):
            await host.ainvoke("graph.add_entity", {"entity_id": f"n{i}", "entity_type": "node"},
                               correlation={"correlation_id": "cli-sess-2"})
        store.close()

        args = argparse.Namespace(session_id="cli-sess-2", store=store_path)
        cmd_session_graph_report(args)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["entities_added"] == 3

    @pytest.mark.asyncio
    async def test_relations_added_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_graph_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-rel", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        await host.ainvoke("graph.add_entity", {"entity_id": "a", "entity_type": "p"},
                           correlation={"correlation_id": "cli-sess-3"})
        await host.ainvoke("graph.add_entity", {"entity_id": "b", "entity_type": "p"},
                           correlation={"correlation_id": "cli-sess-3"})
        await host.ainvoke("graph.add_relation",
                           {"from_entity_id": "a", "to_entity_id": "b", "relation_type": "knows"},
                           correlation={"correlation_id": "cli-sess-3"})
        store.close()

        args = argparse.Namespace(session_id="cli-sess-3", store=store_path)
        cmd_session_graph_report(args)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["relations_added"] == 1

    @pytest.mark.asyncio
    async def test_queries_and_traversals_counted_separately(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_graph_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-qt", store=store)
        kg = InMemoryKnowledgeGraph()
        register_knowledge_graph_capability(host, kg)
        kg.add_entity("s", "node")
        await host.ainvoke("graph.query_entities", {},
                           correlation={"correlation_id": "cli-sess-4"})
        await host.ainvoke("graph.traverse", {"start_id": "s"},
                           correlation={"correlation_id": "cli-sess-4"})
        store.close()

        args = argparse.Namespace(session_id="cli-sess-4", store=store_path)
        cmd_session_graph_report(args)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["queries"] == 1
        assert data["traversals"] == 1


# ── Integration test ──────────────────────────────────────────────────────────


def test_graph_ingest_retrieve_pipeline():
    """Graph entities can feed into a retrieval index via their label and properties."""
    from chp_core import InMemoryKeywordRetrievalCapability

    kg = InMemoryKnowledgeGraph()
    kg.add_entity("p1", "person", label="Alice", properties={"bio": "python engineer"})
    kg.add_entity("p2", "person", label="Bob", properties={"bio": "evidence governance expert"})
    kg.add_entity("p3", "person", label="Carol", properties={"bio": "distributed systems"})

    persons = kg.query_entities(entity_type="person").entities
    docs = [
        {
            "source_id": e.entity_id,
            "content": f"{e.label} {e.properties.get('bio', '')}",
            "title": e.label or e.entity_id,
        }
        for e in persons
    ]

    retrieval_cap = InMemoryKeywordRetrievalCapability(docs)
    result = retrieval_cap.retrieve("python")
    assert result.result_count > 0
    assert result.source_refs[0].source_id == "p1"
