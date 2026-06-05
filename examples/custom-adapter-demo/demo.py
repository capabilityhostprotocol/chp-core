"""Custom adapter authoring demo.

Shows how to build a first-class CHP adapter from scratch:
- BaseAdapter subclass with adapter_id / adapter_name class attributes
- @capability decorator with rich metadata: category, risk, status, tags,
  invariants, emits, input_schema
- InvariantDescriptor enforcing required payload fields (denial on violation)
- ctx.emit() for structured mid-execution events
- register_adapter() wiring
- host.discover() filtering by category, tags, risk, status
- host.query_evidence() and host.evidence_count()

Run:
    PYTHONPATH=packages/python python examples/custom-adapter-demo/demo.py
"""

from __future__ import annotations

import json

from chp_core import (
    BaseAdapter,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    capability,
    register_adapter,
)
from chp_core.host import CapabilityExecutionContext
from chp_core.types import CapabilityCategory, InvariantDescriptor


class DocumentAdapter(BaseAdapter):
    """Search and ingest documents with full CHP evidence and governance."""

    adapter_id = "docs"
    adapter_name = "Document Store Adapter"
    adapter_description = "Governed document search and ingestion capabilities."
    adapter_version = "1.0.0"
    adapter_tags = ["documents", "data"]
    adapter_category = CapabilityCategory.DATA_KNOWLEDGE

    @capability(
        id="docs.search",
        version="1.0.0",
        description="Search the document store and return matching entries.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        risk="low",
        status="certified",
        tags=["read", "search", "documents"],
        emits=["execution_started", "search_executed", "execution_completed"],
        input_schema={
            "type": "object",
            "required": ["query"],
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
        },
        output_schema={
            "type": "object",
            "properties": {"results": {"type": "array"}, "query": {"type": "string"}},
        },
    )
    def search(self, ctx: CapabilityExecutionContext, payload: dict) -> dict:
        query = payload["query"]
        limit = payload.get("limit", 5)
        # Emit a structured event mid-execution (visible in evidence replay)
        ctx.emit("search_executed", {"query": query, "result_count": 2}, redacted=False)
        return {"results": [f"doc:{i}" for i in range(min(2, limit))], "query": query}

    @capability(
        id="docs.ingest",
        version="1.0.0",
        description="Ingest a document into the store.",
        category=CapabilityCategory.DATA_KNOWLEDGE,
        risk="medium",
        status="experimental",
        tags=["write", "ingest", "documents"],
        invariants=[
            InvariantDescriptor(
                id="require-doc-fields",
                kind="required_payload_fields",
                description="Both doc_id and content must be present.",
                enforcement="host",
                failure_behavior="deny",
                parameters={"fields": ["doc_id", "content"]},
            ),
        ],
        emits=["execution_started", "doc_indexed", "execution_completed"],
        input_schema={
            "type": "object",
            "required": ["doc_id", "content"],
            "properties": {
                "doc_id":  {"type": "string"},
                "content": {"type": "string"},
            },
        },
    )
    def ingest(self, ctx: CapabilityExecutionContext, payload: dict) -> dict:
        # Emit a custom structured event with indexing metadata
        ctx.emit("doc_indexed", {
            "doc_id": payload["doc_id"],
            "bytes":  len(payload.get("content", "")),
        }, redacted=False)
        return {"ingested": True, "doc_id": payload["doc_id"]}


if __name__ == "__main__":
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost("docs-host", store=store)
    register_adapter(host, DocumentAdapter())

    corr = "docs-demo"

    # --- Discovery filtering ---
    print("=== Discovery Filtering ===\n")
    data_caps      = host.discover(category=CapabilityCategory.DATA_KNOWLEDGE)
    search_caps    = host.discover(tags=["search"])
    write_caps     = host.discover(tags=["write"])
    medium_risk    = host.discover(risk="medium")
    experimental   = host.discover(status="experimental")
    certified      = host.discover(status="certified")

    print(f"  category=data_knowledge: {[c['id'] for c in data_caps['capabilities']]}")
    print(f"  tags=['search']:         {[c['id'] for c in search_caps['capabilities']]}")
    print(f"  tags=['write']:          {[c['id'] for c in write_caps['capabilities']]}")
    print(f"  risk='medium':           {[c['id'] for c in medium_risk['capabilities']]}")
    print(f"  status='experimental':   {[c['id'] for c in experimental['capabilities']]}")
    print(f"  status='certified':      {[c['id'] for c in certified['capabilities']]}")

    # --- Invocations ---
    print("\n=== Invocations ===\n")
    search_result  = host.invoke("docs.search", {"query": "CHP governance", "limit": 3}, correlation_id=corr)
    ingest_result  = host.invoke("docs.ingest", {"doc_id": "doc-001", "content": "CHP enables governed agents."}, correlation_id=corr)
    # Invariant denial — missing required field 'content'
    denied_result  = host.invoke("docs.ingest", {"doc_id": "doc-002"}, correlation_id=corr)

    print(f"  search outcome:  {search_result.outcome}")
    print(f"  search result:   {search_result.data}")
    print(f"  ingest outcome:  {ingest_result.outcome}")
    print(f"  denied outcome:  {denied_result.outcome}")
    if denied_result.denial:
        print(f"  denial reason:   {denied_result.denial}")

    # --- Evidence querying ---
    print("\n=== Evidence Querying ===\n")
    all_evidence   = host.query_evidence()
    search_ev      = host.query_evidence(capability_id="docs.search")
    success_ingest = host.query_evidence(capability_id="docs.ingest", outcome="success")
    denied_ev      = host.query_evidence(outcome="denied")
    total          = host.evidence_count(corr)

    print(f"  total events in correlation: {total}")
    print(f"  all evidence events:         {len(all_evidence)}")
    print(f"  docs.search events:          {len(search_ev)}")
    print(f"  docs.ingest successes:       {len(success_ingest)}")
    print(f"  denied events:               {len(denied_ev)}")

    # --- Custom doc_indexed events ---
    print("\n=== Custom 'doc_indexed' Events (emitted by ctx.emit()) ===\n")
    custom_events = [
        e for e in store.by_correlation(corr)
        if e["event_type"] == "doc_indexed"
    ]
    for ev in custom_events:
        print(json.dumps(ev["payload"], indent=2))

    # --- search_executed event ---
    print("\n=== Custom 'search_executed' Event ===\n")
    search_executed = [
        e for e in store.by_correlation(corr)
        if e["event_type"] == "search_executed"
    ]
    for ev in search_executed:
        print(json.dumps(ev["payload"], indent=2))
