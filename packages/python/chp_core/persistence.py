"""Convenience wiring for all SQLite-backed capability implementations.

Usage::

    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.persistence import setup_sqlite_capabilities

    store = SQLiteEvidenceStore(".chp/evidence.sqlite")
    host = LocalCapabilityHost("my-agent", store=store)
    managers = setup_sqlite_capabilities(host, base_dir=".chp")
    # managers.keys(): state_machine, event_bus, ingestion, retrieval, graph, incident
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


def setup_sqlite_capabilities(host: Any, *, base_dir: str = ".chp") -> dict[str, Any]:
    """Wire all SQLite-backed capability implementations onto *host*.

    Creates the base directory if it does not exist. Returns a dict of all
    manager instances keyed by short name for direct programmatic access.
    """
    from .events import SQLiteEventBus, register_event_bus_capability
    from .incident import SQLiteIncidentManager, register_incident_capability
    from .ingestion import SQLiteIngestionCapability, register_ingestion_capability
    from .knowledge_graph import SQLiteKnowledgeGraph, register_knowledge_graph_capability
    from .retrieval import SQLiteKeywordRetrievalCapability, register_retrieval_capability
    from .state_machine import SQLiteStateMachine, register_state_machine_capability

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    sm = SQLiteStateMachine(str(base / "state_machines.sqlite"))
    register_state_machine_capability(host, sm)

    bus = SQLiteEventBus(str(base / "events.sqlite"))
    register_event_bus_capability(host, bus)

    docs_path = str(base / "documents.sqlite")
    ingestion = SQLiteIngestionCapability(docs_path)
    register_ingestion_capability(host, ingestion)

    retrieval = SQLiteKeywordRetrievalCapability(docs_path)
    register_retrieval_capability(host, retrieval)

    graph = SQLiteKnowledgeGraph(str(base / "graph.sqlite"))
    register_knowledge_graph_capability(host, graph)

    incident = SQLiteIncidentManager(str(base / "incidents.sqlite"))
    register_incident_capability(host, incident)

    return {
        "state_machine": sm,
        "event_bus": bus,
        "ingestion": ingestion,
        "retrieval": retrieval,
        "graph": graph,
        "incident": incident,
    }
