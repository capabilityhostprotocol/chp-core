"""RetrievalCapability — governed RAG base class for CHP agents.

Every retrieval call emits hash-chained evidence events so source citations
are auditable and replayable without external dependencies.

Usage (standalone)::

    cap = InMemoryKeywordRetrievalCapability([
        {"source_id": "doc-1", "content": "the quick brown fox", "title": "Doc 1"},
    ])
    result = cap.retrieve("quick fox", top_k=3)

Usage (as a CHP capability on a host)::

    host = LocalCapabilityHost("my-host", store=store)
    cap = InMemoryKeywordRetrievalCapability(documents)
    register_retrieval_capability(host, cap)
    # host.invoke("retrieval.query", {"query": "...", "top_k": 5})
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable, Literal

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    JSON,
    RetrievalResult,
    SourceRef,
)

if TYPE_CHECKING:
    from .host import LocalCapabilityHost

_RETRIEVAL_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "retrieval_started",
    "retrieval_completed",
    "retrieval_failed",
]


class RetrievalCapability:
    """Abstract base for governed retrieval capabilities.

    Subclass and implement ``retrieve()`` — the handler wired by
    ``register_retrieval_capability`` handles evidence emission.
    """

    capability_id: str = "retrieval.query"
    capability_version: str = "0.1.0"
    retrieval_type: Literal["keyword", "vector", "hybrid"] = "keyword"
    description: str = "Governed retrieval capability."

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> RetrievalResult:
        raise NotImplementedError

    def as_capability_descriptor(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            id=self.capability_id,
            version=self.capability_version,
            description=self.description,
            category=CapabilityCategory.DATA_KNOWLEDGE,
            tags=["retrieval", self.retrieval_type],
            emits=list(_RETRIEVAL_EMITS),
        )


class InMemoryKeywordRetrievalCapability(RetrievalCapability):
    """Stdlib-only keyword retrieval over an in-memory document corpus.

    Scores each document by normalised term-frequency of query tokens.
    Zero external dependencies; suitable for tests and demos.

    Documents are dicts with:
    - ``source_id`` (required)
    - ``content``   (required, searched)
    - ``title``     (optional)
    - ``uri``       (optional)
    """

    retrieval_type: Literal["keyword", "vector", "hybrid"] = "keyword"

    def __init__(
        self,
        documents: list[dict],
        *,
        capability_id: str = "retrieval.query",
        capability_version: str = "0.1.0",
        description: str = "In-memory keyword retrieval.",
    ) -> None:
        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description
        self._docs = documents

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> RetrievalResult:
        t0 = time.perf_counter()
        terms = query.lower().split()
        scored: list[tuple[float, dict]] = []
        for doc in self._docs:
            text = doc.get("content", "").lower()
            word_count = len(text.split()) + 1
            score = sum(text.count(t) for t in terms) / word_count
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        refs = [
            SourceRef(
                source_id=doc["source_id"],
                title=doc.get("title"),
                score=round(sc, 4),
                uri=doc.get("uri"),
            )
            for sc, doc in scored[:top_k]
        ]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return RetrievalResult(
            query=query,
            source_refs=refs,
            result_count=len(refs),
            latency_ms=latency_ms,
        )


class SQLiteKeywordRetrievalCapability(RetrievalCapability):
    """SQLite-backed keyword retrieval — reads docs written by SQLiteIngestionCapability."""

    retrieval_type: Literal["keyword", "vector", "hybrid"] = "keyword"

    def __init__(
        self,
        store_path: str = ".chp/documents.sqlite",
        *,
        capability_id: str = "retrieval.query",
        capability_version: str = "0.1.0",
        description: str = "SQLite-backed keyword retrieval.",
    ) -> None:
        import sqlite3
        from pathlib import Path

        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description
        p = Path(store_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                source_id    TEXT PRIMARY KEY,
                content      TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                byte_count   INTEGER NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'text/plain',
                title        TEXT,
                uri          TEXT,
                ingested_at  TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> RetrievalResult:
        t0 = time.perf_counter()
        terms = query.lower().split()
        rows = self._conn.execute(
            "SELECT source_id, content, title, uri FROM documents"
        ).fetchall()
        scored: list[tuple[float, tuple]] = []
        for row in rows:
            source_id, content, title, uri = row
            text = (content or "").lower()
            word_count = len(text.split()) + 1
            score = sum(text.count(t) for t in terms) / word_count
            if score > 0:
                scored.append((score, row))
        scored.sort(key=lambda x: x[0], reverse=True)
        refs = [
            SourceRef(
                source_id=row[0],
                title=row[2],
                score=round(sc, 4),
                uri=row[3],
            )
            for sc, row in scored[:top_k]
        ]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return RetrievalResult(
            query=query,
            source_refs=refs,
            result_count=len(refs),
            latency_ms=latency_ms,
        )

    def close(self) -> None:
        self._conn.close()


def _cosine(a: list[float], b: list[float]) -> float:
    """Stdlib-only cosine similarity — no numpy required."""
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


class VectorRetrievalCapability(RetrievalCapability):
    """Abstract base for vector retrieval capabilities.

    Subclasses receive ``embed_fn`` — a callable that maps a text string to a
    list of floats. The embedding provider is entirely user-supplied, keeping
    the SDK dependency-free.
    """

    retrieval_type: Literal["keyword", "vector", "hybrid"] = "vector"

    def __init__(
        self,
        embed_fn: Callable[[str], list[float]],
        *,
        capability_id: str = "retrieval.query",
        capability_version: str = "0.1.0",
        description: str = "Vector retrieval capability.",
    ) -> None:
        self.embed_fn = embed_fn
        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description


class InMemoryVectorRetrievalCapability(VectorRetrievalCapability):
    """Cosine-similarity retrieval over an in-memory vector store.

    Documents are embedded at construction time; call ``ingest()`` to add more
    without restarting. Zero external dependencies — uses ``_cosine()`` which
    requires only stdlib.

    Documents are dicts with:
    - ``source_id`` (required)
    - ``content``   (required, embedded)
    - ``title``     (optional)
    - ``uri``       (optional)
    """

    def __init__(
        self,
        embed_fn: Callable[[str], list[float]],
        documents: list[dict] | None = None,
        *,
        capability_id: str = "retrieval.query",
        capability_version: str = "0.1.0",
        description: str = "In-memory vector retrieval.",
    ) -> None:
        super().__init__(
            embed_fn,
            capability_id=capability_id,
            capability_version=capability_version,
            description=description,
        )
        self._items: list[tuple[str, list[float], dict]] = []
        for doc in (documents or []):
            self._embed_and_store(doc)

    def _embed_and_store(self, doc: dict) -> None:
        content = doc.get("content", "")
        vector = self.embed_fn(content)
        self._items.append((doc["source_id"], vector, doc))

    def ingest(self, doc: dict) -> None:
        """Embed *doc* and add it to the in-memory store."""
        self._embed_and_store(doc)

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> RetrievalResult:
        t0 = time.perf_counter()
        q_vec = self.embed_fn(query)
        scored: list[tuple[float, dict]] = []
        for source_id, vec, doc in self._items:
            score = _cosine(q_vec, vec)
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        refs = [
            SourceRef(
                source_id=doc["source_id"],
                title=doc.get("title"),
                score=round(sc, 4),
                uri=doc.get("uri"),
            )
            for sc, doc in scored[:top_k]
        ]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return RetrievalResult(
            query=query,
            source_refs=refs,
            result_count=len(refs),
            latency_ms=latency_ms,
            retrieval_type="vector",
        )


class SQLiteVectorRetrievalCapability(VectorRetrievalCapability):
    """Vector retrieval backed by SQLite.

    Shares the same ``documents.sqlite`` file as ``SQLiteIngestionCapability``
    so no separate ingestion step is required when both capabilities are
    registered. Embeddings are stored in a separate ``embeddings`` table.

    ``retrieve()`` loads all embeddings into Python and computes cosine
    similarity in-process. Suitable for corpora up to ~10k documents; for
    larger datasets, the inner loop can be swapped for ``sqlite-vec`` without
    any API change.
    """

    def __init__(
        self,
        store_path: str = ".chp/documents.sqlite",
        embed_fn: Callable[[str], list[float]] | None = None,
        *,
        capability_id: str = "retrieval.query",
        capability_version: str = "0.1.0",
        description: str = "SQLite-backed vector retrieval.",
    ) -> None:
        import json as _json
        import sqlite3
        from pathlib import Path

        if embed_fn is None:
            raise ValueError("SQLiteVectorRetrievalCapability requires embed_fn")

        super().__init__(
            embed_fn,
            capability_id=capability_id,
            capability_version=capability_version,
            description=description,
        )
        self._json = _json
        p = Path(store_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                source_id    TEXT PRIMARY KEY,
                content      TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                byte_count   INTEGER NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'text/plain',
                title        TEXT,
                uri          TEXT,
                ingested_at  TEXT NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS embeddings (
                source_id   TEXT PRIMARY KEY,
                vector_json TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def embed_and_store(self, source_id: str, text: str) -> None:
        """Compute and persist the embedding for *source_id*."""
        vector = self.embed_fn(text)
        self._conn.execute(
            "INSERT OR REPLACE INTO embeddings (source_id, vector_json) VALUES (?, ?)",
            (source_id, self._json.dumps(vector)),
        )
        self._conn.commit()

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> RetrievalResult:
        t0 = time.perf_counter()
        q_vec = self.embed_fn(query)
        rows = self._conn.execute(
            """SELECT e.source_id, e.vector_json, d.title, d.uri
               FROM embeddings e
               LEFT JOIN documents d ON d.source_id = e.source_id"""
        ).fetchall()
        scored: list[tuple[float, tuple]] = []
        for row in rows:
            source_id, vector_json, title, uri = row
            vec: list[float] = self._json.loads(vector_json)
            score = _cosine(q_vec, vec)
            if score > 0:
                scored.append((score, row))
        scored.sort(key=lambda x: x[0], reverse=True)
        refs = [
            SourceRef(
                source_id=row[0],
                title=row[2],
                score=round(sc, 4),
                uri=row[3],
            )
            for sc, row in scored[:top_k]
        ]
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return RetrievalResult(
            query=query,
            source_refs=refs,
            result_count=len(refs),
            latency_ms=latency_ms,
            retrieval_type="vector",
        )

    def close(self) -> None:
        self._conn.close()


# ── Host registration ──────────────────────────────────────────────────────────


def register_retrieval_capability(
    host: "LocalCapabilityHost",
    cap: RetrievalCapability,
) -> None:
    """Register *cap* as a ``retrieval.query`` capability on *host*.

    The registered handler emits ``retrieval_started``, ``retrieval_completed``
    (or ``retrieval_failed``) events into the host's hash-chained evidence store.
    """

    async def _query(ctx: Any, payload: JSON) -> JSON:
        query = str(payload.get("query", ""))
        top_k = int(payload.get("top_k", 5))
        filters = payload.get("filters")

        ctx.emit("execution_started", {"capability_id": cap.capability_id}, redacted=False)
        ctx.emit("retrieval_started", {"query": query, "top_k": top_k}, redacted=False)
        t0 = time.perf_counter()
        try:
            result = cap.retrieve(query, top_k=top_k, filters=filters)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            event_payload: JSON = {
                "query": query,
                "top_k": top_k,
                "result_count": result.result_count,
                "latency_ms": latency_ms,
                "retrieval_type": result.retrieval_type,
                "source_refs": [r.to_dict() for r in result.source_refs],
            }
            ctx.emit("retrieval_completed", event_payload, redacted=False)
            ctx.emit("execution_completed", {"outcome": "success"}, redacted=False)
            return result.to_dict()
        except Exception as exc:
            err: JSON = {"reason": str(exc), "exception_type": type(exc).__name__}
            ctx.emit("retrieval_failed", err, redacted=False)
            ctx.emit("execution_failed", err, redacted=False)
            raise

    host.register(cap.as_capability_descriptor(), _query)
