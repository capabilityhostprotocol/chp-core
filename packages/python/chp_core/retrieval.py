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
from typing import TYPE_CHECKING, Any, Literal

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
