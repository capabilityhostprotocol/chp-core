"""Tests for SQLite-backed capability implementations — persistence wave v0.6.0."""

from __future__ import annotations

import os
import tempfile

import pytest

from chp_core import (
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    SQLiteEventBus,
    SQLiteIncidentManager,
    SQLiteIngestionCapability,
    SQLiteKeywordRetrievalCapability,
    SQLiteKnowledgeGraph,
    SQLiteStateMachine,
    setup_sqlite_capabilities,
)
from chp_core.types import StateMachineDefinition


# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def sm_path(tmp_path):
    return str(tmp_path / "state_machines.sqlite")


@pytest.fixture
def inc_path(tmp_path):
    return str(tmp_path / "incidents.sqlite")


@pytest.fixture
def bus_path(tmp_path):
    return str(tmp_path / "events.sqlite")


@pytest.fixture
def docs_path(tmp_path):
    return str(tmp_path / "documents.sqlite")


@pytest.fixture
def graph_path(tmp_path):
    return str(tmp_path / "graph.sqlite")


@pytest.fixture
def simple_defn():
    return StateMachineDefinition(
        states=["pending", "running", "done"],
        transitions={"pending": ["running"], "running": ["done"]},
        initial_state="pending",
        terminal_states=["done"],
    )


# ── SQLiteStateMachine ────────────────────────────────────────────────────────


def test_sqlite_state_machine_create(sm_path, simple_defn):
    sm = SQLiteStateMachine(sm_path)
    record = sm.create("test", simple_defn, {})
    assert record.machine_id.startswith("sm_")
    assert record.current_state == "pending"
    assert record.status == "queued"
    sm.close()


def test_sqlite_state_machine_transition(sm_path, simple_defn):
    sm = SQLiteStateMachine(sm_path)
    record = sm.create("test", simple_defn, {})
    result = sm.transition(record.machine_id, "running")
    assert result.allowed is True
    assert result.to_state == "running"
    sm.close()


def test_sqlite_state_machine_terminal_transition(sm_path, simple_defn):
    sm = SQLiteStateMachine(sm_path)
    record = sm.create("test", simple_defn, {})
    sm.transition(record.machine_id, "running")
    result = sm.transition(record.machine_id, "done")
    assert result.allowed is True
    assert result.to_state == "done"
    fetched = sm.get(record.machine_id)
    assert fetched.status == "done"
    sm.close()


def test_sqlite_state_machine_persistence(sm_path, simple_defn):
    """State and history survive closing and reopening the database."""
    sm1 = SQLiteStateMachine(sm_path)
    record = sm1.create("persistent", simple_defn, {"tag": "v1"})
    sm1.transition(record.machine_id, "running")
    sm1.close()

    sm2 = SQLiteStateMachine(sm_path)
    reloaded = sm2.get(record.machine_id)
    assert reloaded is not None
    assert reloaded.current_state == "running"
    assert reloaded.context == {"tag": "v1"}
    assert len(reloaded.history) == 1
    assert reloaded.history[0]["from"] == "pending"
    sm2.close()


def test_sqlite_state_machine_list_with_status(sm_path, simple_defn):
    sm = SQLiteStateMachine(sm_path)
    r1 = sm.create("m1", simple_defn, {})
    r2 = sm.create("m2", simple_defn, {})
    sm.transition(r1.machine_id, "running")
    queued = sm.list_machines(status="queued")
    assert len(queued) == 1
    assert queued[0].machine_id == r2.machine_id
    sm.close()


# ── SQLiteEventBus ────────────────────────────────────────────────────────────


def test_sqlite_event_bus_emit(bus_path):
    bus = SQLiteEventBus(bus_path)
    record = bus.emit_event("order.placed", "shop-service", {"order_id": "o1"})
    assert record.event_id.startswith("devt_")
    assert record.event_type == "order.placed"
    assert record.data_hash.startswith("sha256:")
    bus.close()


def test_sqlite_event_bus_query_by_type(bus_path):
    bus = SQLiteEventBus(bus_path)
    bus.emit_event("order.placed", "shop", {"order_id": "o1"})
    bus.emit_event("order.shipped", "warehouse", {"order_id": "o1"})
    result = bus.query_events(event_type="order.placed")
    assert result.event_count == 1
    assert result.events[0].event_type == "order.placed"
    bus.close()


def test_sqlite_event_bus_persistence(bus_path):
    """Emitted events survive closing and reopening the database."""
    bus1 = SQLiteEventBus(bus_path)
    bus1.emit_event("user.created", "auth-service", {"user_id": "u1"})
    bus1.close()

    bus2 = SQLiteEventBus(bus_path)
    result = bus2.query_events()
    assert result.event_count == 1
    assert result.events[0].event_type == "user.created"
    bus2.close()


# ── SQLiteIngestionCapability + SQLiteKeywordRetrievalCapability ──────────────


def test_sqlite_ingestion_basic(docs_path):
    cap = SQLiteIngestionCapability(docs_path)
    result = cap.ingest("The quick brown fox", title="Fox doc", uri="file://fox.txt")
    assert result.record_count == 1
    assert result.records[0].content_hash.startswith("sha256:")
    cap.close()


def test_sqlite_retrieval_finds_ingested_docs(docs_path):
    """SQLiteKeywordRetrievalCapability reads docs written by SQLiteIngestionCapability."""
    ingestion = SQLiteIngestionCapability(docs_path)
    ingestion.ingest("The quick brown fox", source_id="fox", title="Fox")
    ingestion.ingest("A lazy dog sleeps", source_id="dog", title="Dog")
    ingestion.close()

    retrieval = SQLiteKeywordRetrievalCapability(docs_path)
    result = retrieval.retrieve("quick fox", top_k=5)
    assert result.result_count >= 1
    assert result.source_refs[0].source_id == "fox"
    retrieval.close()


def test_sqlite_ingestion_persistence(docs_path):
    """Ingested documents survive closing and reopening."""
    cap1 = SQLiteIngestionCapability(docs_path)
    cap1.ingest("Persistent document content", source_id="doc-persist")
    cap1.close()

    cap2 = SQLiteKeywordRetrievalCapability(docs_path)
    result = cap2.retrieve("persistent document")
    assert result.result_count == 1
    assert result.source_refs[0].source_id == "doc-persist"
    cap2.close()


def test_sqlite_ingestion_upsert(docs_path):
    """Re-ingesting the same source_id updates the document."""
    cap = SQLiteIngestionCapability(docs_path)
    cap.ingest("original content", source_id="doc-1")
    cap.ingest("updated content", source_id="doc-1")
    cap.close()

    retrieval = SQLiteKeywordRetrievalCapability(docs_path)
    result = retrieval.retrieve("updated", top_k=5)
    assert result.result_count == 1
    retrieval.close()


# ── SQLiteKnowledgeGraph ──────────────────────────────────────────────────────


def test_sqlite_graph_add_entity(graph_path):
    kg = SQLiteKnowledgeGraph(graph_path)
    entity = kg.add_entity("e1", "person", label="Alice", properties={"age": 30})
    assert entity.entity_id == "e1"
    assert entity.entity_type == "person"
    assert entity.properties["age"] == 30
    kg.close()


def test_sqlite_graph_add_relation(graph_path):
    kg = SQLiteKnowledgeGraph(graph_path)
    kg.add_entity("e1", "person")
    kg.add_entity("e2", "company")
    rel = kg.add_relation("e1", "e2", "works_at")
    assert rel.from_entity_id == "e1"
    assert rel.relation_type == "works_at"
    kg.close()


def test_sqlite_graph_traverse(graph_path):
    kg = SQLiteKnowledgeGraph(graph_path)
    kg.add_entity("a", "node")
    kg.add_entity("b", "node")
    kg.add_entity("c", "node")
    kg.add_relation("a", "b", "connects")
    kg.add_relation("b", "c", "connects")
    result = kg.traverse("a", depth=2)
    ids = {e.entity_id for e in result.entities}
    assert "b" in ids and "c" in ids
    kg.close()


def test_sqlite_graph_persistence(graph_path):
    """Entities and relations survive closing and reopening."""
    kg1 = SQLiteKnowledgeGraph(graph_path)
    kg1.add_entity("n1", "server", label="web-01")
    kg1.add_entity("n2", "server", label="db-01")
    kg1.add_relation("n1", "n2", "depends_on")
    kg1.close()

    kg2 = SQLiteKnowledgeGraph(graph_path)
    result = kg2.query_entities(entity_type="server")
    assert result.entity_count == 2
    kg2.close()


# ── SQLiteIncidentManager ─────────────────────────────────────────────────────


def test_sqlite_incident_open(inc_path):
    mgr = SQLiteIncidentManager(inc_path)
    inc = mgr.open("Service down", "P1")
    assert inc.incident_id.startswith("inc_")
    assert inc.status == "open"
    assert len(inc.timeline) == 1
    mgr.close_conn()


def test_sqlite_incident_lifecycle(inc_path):
    mgr = SQLiteIncidentManager(inc_path)
    inc = mgr.open("Memory leak", "P2")
    mgr.escalate(inc.incident_id, note="paging")
    mgr.resolve(inc.incident_id)
    closed = mgr.close(inc.incident_id)
    assert closed.status == "closed"
    assert len(closed.timeline) == 4
    mgr.close_conn()


def test_sqlite_incident_persistence(inc_path):
    """Incidents survive closing and reopening the database."""
    mgr1 = SQLiteIncidentManager(inc_path)
    inc = mgr1.open("Disk full", "P3")
    mgr1.escalate(inc.incident_id)
    mgr1.close_conn()

    mgr2 = SQLiteIncidentManager(inc_path)
    reloaded = mgr2.get(inc.incident_id)
    assert reloaded is not None
    assert reloaded.status == "escalated"
    assert reloaded.title == "Disk full"
    assert len(reloaded.timeline) == 2
    mgr2.close_conn()


def test_sqlite_incident_list(inc_path):
    mgr = SQLiteIncidentManager(inc_path)
    mgr.open("A", "P1")
    mgr.open("B", "P2")
    inc_c = mgr.open("C", "P3")
    mgr.resolve(mgr.escalate(inc_c.incident_id).incident_id)
    open_incidents = mgr.list_incidents(status="open")
    assert len(open_incidents) == 2
    mgr.close_conn()


# ── setup_sqlite_capabilities convenience function ────────────────────────────


@pytest.mark.asyncio
async def test_setup_sqlite_capabilities(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "evidence.sqlite"))
    host = LocalCapabilityHost("test-persistence", store=store)
    managers = setup_sqlite_capabilities(host, base_dir=str(tmp_path))

    assert set(managers.keys()) == {
        "state_machine", "event_bus", "ingestion", "retrieval", "graph", "incident"
    }

    # smoke test: all capabilities are invocable
    r_sm = await host.ainvoke(
        "state_machine.create",
        {
            "name": "smoke",
            "definition": {
                "states": ["a", "b"],
                "transitions": {"a": ["b"]},
                "initial_state": "a",
                "terminal_states": ["b"],
            },
            "context": {},
        },
    )
    assert r_sm.success

    r_ev = await host.ainvoke(
        "events.emit",
        {"event_type": "smoke.test", "source": "test", "data": {}},
    )
    assert r_ev.success

    r_ingest = await host.ainvoke(
        "ingestion.ingest",
        {"content": "hello world", "title": "Smoke"},
    )
    assert r_ingest.success

    store.close()
