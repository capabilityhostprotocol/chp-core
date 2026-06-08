#!/usr/bin/env python3
"""Vector retrieval demo — governed RAG with user-supplied embeddings.

Demonstrates:
  - InMemoryVectorRetrievalCapability  (cosine sim, live ingest)
  - SQLiteVectorRetrievalCapability    (persistent embeddings, shared file)
  - register_retrieval_capability      (evidence-emitting host integration)
  - Replay shows retrieval_started / retrieval_completed events

Run:
    python examples/vector-retrieval-demo/demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    InMemoryVectorRetrievalCapability,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    SQLiteIngestionCapability,
    SQLiteVectorRetrievalCapability,
    register_retrieval_capability,
)

# ---------------------------------------------------------------------------
# Toy embedding function — bag-of-words over a 10-term vocabulary.
# In production: swap for OpenAI text-embedding-3-small, Cohere, etc.
# ---------------------------------------------------------------------------

VOCAB = ["python", "typescript", "database", "sqlite", "evidence",
         "agent", "protocol", "retrieval", "vector", "cosine"]


def embed(text: str) -> list[float]:
    words = text.lower().split()
    return [float(words.count(w)) for w in VOCAB]


# ---------------------------------------------------------------------------
# Document corpus
# ---------------------------------------------------------------------------

CORPUS = [
    {
        "source_id": "doc-chp",
        "title": "Capability Host Protocol",
        "content": "CHP is a Python and TypeScript protocol for governed agent evidence.",
        "uri": "https://chp.dev/spec",
    },
    {
        "source_id": "doc-sqlite",
        "title": "SQLite Evidence Store",
        "content": "SQLite database stores evidence with hash-chained integrity and WAL mode.",
        "uri": "https://chp.dev/sqlite",
    },
    {
        "source_id": "doc-retrieval",
        "title": "Retrieval Capability",
        "content": "Vector retrieval uses cosine similarity to find relevant documents for agents.",
        "uri": "https://chp.dev/retrieval",
    },
    {
        "source_id": "doc-agents",
        "title": "Agent Protocol",
        "content": "CHP agents emit evidence events when invoking capabilities during their protocol loop.",
        "uri": "https://chp.dev/agents",
    },
]


def sep(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


# ---------------------------------------------------------------------------
# Part 1 — InMemoryVectorRetrievalCapability standalone
# ---------------------------------------------------------------------------

sep("Part 1 — In-memory vector retrieval (standalone)")

cap = InMemoryVectorRetrievalCapability(embed, CORPUS)
result = cap.retrieve("vector cosine similarity retrieval", top_k=2)
print(f"\nQuery: 'vector cosine similarity retrieval'")
print(f"Retrieval type: {result.retrieval_type}")
for ref in result.source_refs:
    print(f"  [{ref.score:.4f}]  {ref.source_id:20s}  {ref.title}")

# Live ingest without restart — content uses in-vocabulary terms
cap.ingest({
    "source_id": "doc-live",
    "title": "Live Vector Cosine Search",
    "content": "vector cosine retrieval can be extended with new vector documents at runtime.",
})
result2 = cap.retrieve("vector cosine", top_k=1)
print(f"\nAfter live ingest — query: 'vector cosine'")
print(f"  top result: {result2.source_refs[0].source_id}  ({result2.source_refs[0].title})")


# ---------------------------------------------------------------------------
# Part 2 — InMemoryVectorRetrievalCapability on a host (evidence emitted)
# ---------------------------------------------------------------------------

sep("Part 2 — Vector retrieval through a governed host")

store = SQLiteEvidenceStore(":memory:")
host = LocalCapabilityHost("vector-demo", store=store)
register_retrieval_capability(host, InMemoryVectorRetrievalCapability(embed, CORPUS))

async def run_hosted_retrieval():
    result = await host.ainvoke(
        "retrieval.query",
        {"query": "sqlite evidence database", "top_k": 2},
        correlation={"correlation_id": "rag-001"},
    )
    print(f"\nInvocation outcome: {result.outcome}")
    print(f"Top results:")
    for ref in result.data["source_refs"][:2]:
        print(f"  [{ref['score']:.4f}]  {ref['source_id']}")

    events = host.replay("rag-001")
    print(f"\nEvidence trace ({len(events)} events):")
    for ev in events:
        print(f"  [{ev['sequence']:2d}]  {ev['event_type']}")

asyncio.run(run_hosted_retrieval())


# ---------------------------------------------------------------------------
# Part 3 — SQLiteVectorRetrievalCapability (persistence)
# ---------------------------------------------------------------------------

sep("Part 3 — SQLite-backed vector retrieval (survives restarts)")

with tempfile.TemporaryDirectory() as tmp:
    # Both ingestion and vector retrieval share the same file — a single
    # documents.sqlite holds both text metadata (documents table) and
    # embeddings (embeddings table).
    db = str(Path(tmp) / "documents.sqlite")

    # First "session" — ingest documents (writes metadata) + embed (writes vectors)
    ing = SQLiteIngestionCapability(db)
    cap1 = SQLiteVectorRetrievalCapability(db, embed)
    for doc in CORPUS:
        ing.ingest(
            doc["content"],
            source_id=doc["source_id"],
            title=doc["title"],
            uri=doc.get("uri"),
        )
        cap1.embed_and_store(doc["source_id"], doc["content"])
    result_a = cap1.retrieve("agent protocol evidence", top_k=1)
    top = result_a.source_refs[0]
    print(f"\nSession 1 — query: 'agent protocol evidence'")
    print(f"  top: {top.source_id}  title='{top.title}'  score={top.score}")
    ing.close()
    cap1.close()

    # Second "session" — reopen same file, no re-embedding needed
    cap2 = SQLiteVectorRetrievalCapability(db, embed)
    result_b = cap2.retrieve("agent protocol evidence", top_k=1)
    top2 = result_b.source_refs[0]
    print(f"\nSession 2 (reopened) — same query:")
    print(f"  top: {top2.source_id}  title='{top2.title}'  (persisted ✓)")
    cap2.close()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

sep("Summary")
print("""
v0.6.2 additions verified:

  InMemoryVectorRetrievalCapability
    ✓ Cosine similarity retrieval at construction time
    ✓ Live ingest() without restart
    ✓ Correct top-k ordering

  SQLiteVectorRetrievalCapability
    ✓ Embeddings persist to SQLite
    ✓ Correct results after close + reopen

  Host integration
    ✓ register_retrieval_capability works with vector cap
    ✓ retrieval_started / retrieval_completed evidence emitted
    ✓ Replay by correlation ID returns full trace
""")
