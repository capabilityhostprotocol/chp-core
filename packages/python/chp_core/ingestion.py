"""Governed data ingestion capability for CHP v0.4.1."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    IngestionRecord,
    IngestionResult,
    new_id,
)

if TYPE_CHECKING:
    pass

_INGESTION_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "ingestion_started",
    "ingestion_completed",
    "ingestion_failed",
]


class IngestionCapability:
    capability_id: str = "ingestion.ingest"
    capability_version: str = "0.1.0"
    description: str = "Governed ingestion capability."

    def ingest(
        self,
        content: str,
        *,
        source_id: str | None = None,
        title: str | None = None,
        uri: str | None = None,
        content_type: str = "text/plain",
    ) -> IngestionResult:
        raise NotImplementedError

    def as_capability_descriptor(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            id=self.capability_id,
            version=self.capability_version,
            description=self.description,
            category=CapabilityCategory.DATA_KNOWLEDGE,
            tags=["ingestion"],
            emits=list(_INGESTION_EMITS),
        )


class InMemoryTextIngestionCapability(IngestionCapability):
    def __init__(
        self,
        *,
        capability_id: str = "ingestion.ingest",
        capability_version: str = "0.1.0",
        description: str = "In-memory text ingestion.",
    ) -> None:
        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description
        self._store: list[dict] = []

    def ingest(
        self,
        content: str,
        *,
        source_id: str | None = None,
        title: str | None = None,
        uri: str | None = None,
        content_type: str = "text/plain",
    ) -> IngestionResult:
        import hashlib
        import time

        t0 = time.perf_counter()
        sid = source_id or new_id("doc")
        raw = content.encode("utf-8")
        content_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        byte_count = len(raw)
        self._store.append({"source_id": sid, "content": content, "title": title, "uri": uri})
        record = IngestionRecord(
            source_id=sid,
            content_hash=content_hash,
            byte_count=byte_count,
            content_type=content_type,
            title=title,
            uri=uri,
        )
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return IngestionResult(
            source_uri=uri,
            records=[record],
            record_count=1,
            total_bytes=byte_count,
            latency_ms=latency_ms,
        )

    def as_retrieval_documents(self) -> list[dict]:
        """Return ingested docs in the format expected by InMemoryKeywordRetrievalCapability."""
        return list(self._store)


def register_ingestion_capability(host: object, cap: IngestionCapability) -> None:
    import time

    async def _ingest(ctx, payload) -> dict:
        content: str = payload.get("content", "")
        source_id: str | None = payload.get("source_id")
        title: str | None = payload.get("title")
        uri: str | None = payload.get("uri")
        content_type: str = payload.get("content_type", "text/plain")

        ctx.emit(
            "execution_started",
            {"capability_id": cap.capability_id, "capability_version": cap.capability_version},
            redacted=False,
        )
        ctx.emit("ingestion_started", {"uri": uri, "content_type": content_type}, redacted=False)

        t0 = time.perf_counter()
        try:
            result = cap.ingest(
                content,
                source_id=source_id,
                title=title,
                uri=uri,
                content_type=content_type,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            ctx.emit(
                "ingestion_failed",
                {"error": str(exc), "latency_ms": latency_ms},
                redacted=False,
            )
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        ctx.emit(
            "ingestion_completed",
            {
                "source_uri": result.source_uri,
                "record_count": result.record_count,
                "total_bytes": result.total_bytes,
                "latency_ms": latency_ms,
                "records": [r.to_dict() for r in result.records],
            },
            redacted=False,
        )
        ctx.emit(
            "execution_completed",
            {"capability_id": cap.capability_id, "outcome": "success"},
            redacted=False,
        )
        return result.to_dict()

    host.register(cap.as_capability_descriptor(), _ingest)
