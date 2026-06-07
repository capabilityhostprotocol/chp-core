"""Governed domain event bus capability for CHP v0.4.4."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    DomainEventQueryResult,
    DomainEventRecord,
    new_id,
    utc_now,
)

_EMIT_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "domain_event_emitted",
    "domain_event_operation_failed",
]

_QUERY_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "domain_events_queried",
    "domain_event_operation_failed",
]


def _data_hash(data: object) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class EventBusCapability:
    capability_id_prefix: str = "events"
    capability_version: str = "0.1.0"
    description: str = "Governed domain event bus."

    def emit_event(
        self,
        event_type: str,
        source: str,
        data: dict[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> DomainEventRecord:
        raise NotImplementedError

    def query_events(
        self,
        *,
        event_type: str | None = None,
        source: str | None = None,
        limit: int | None = None,
    ) -> DomainEventQueryResult:
        raise NotImplementedError


class InMemoryEventBus(EventBusCapability):
    def __init__(
        self,
        *,
        capability_id_prefix: str = "events",
        capability_version: str = "0.1.0",
        description: str = "In-memory domain event bus.",
    ) -> None:
        self.capability_id_prefix = capability_id_prefix
        self.capability_version = capability_version
        self.description = description
        self._events: list[DomainEventRecord] = []

    def emit_event(
        self,
        event_type: str,
        source: str,
        data: dict[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> DomainEventRecord:
        record = DomainEventRecord(
            event_id=new_id("devt"),
            event_type=event_type,
            source=source,
            data=data,
            data_hash=_data_hash(data),
            emitted_at=utc_now(),
            correlation_id=correlation_id,
        )
        self._events.append(record)
        return record

    def query_events(
        self,
        *,
        event_type: str | None = None,
        source: str | None = None,
        limit: int | None = None,
    ) -> DomainEventQueryResult:
        events = list(self._events)
        if event_type is not None:
            events = [e for e in events if e.event_type == event_type]
        if source is not None:
            events = [e for e in events if e.source == source]
        if limit is not None:
            events = events[:limit]
        return DomainEventQueryResult(
            events=events,
            event_count=len(events),
            event_type_filter=event_type,
        )


def register_event_bus_capability(host: Any, bus: EventBusCapability) -> None:
    prefix = bus.capability_id_prefix
    version = bus.capability_version

    # ── events.emit ───────────────────────────────────────────────────────────

    emit_desc = CapabilityDescriptor(
        id=f"{prefix}.emit",
        version=version,
        description="Emit a named domain event to the event bus.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["events"],
        emits=list(_EMIT_EMITS),
    )

    async def _emit_event(ctx, payload) -> dict:
        event_type: str = payload.get("event_type", "unknown")
        source: str = payload.get("source", "")
        data: dict[str, Any] = payload.get("data") or {}
        correlation_id: str | None = payload.get("correlation_id")

        ctx.emit(
            "execution_started",
            {"capability_id": emit_desc.id, "capability_version": version},
            redacted=False,
        )
        try:
            record = bus.emit_event(
                event_type, source, data, correlation_id=correlation_id
            )
        except Exception as exc:
            ctx.emit(
                "domain_event_operation_failed",
                {"error": str(exc), "operation": "emit"},
                redacted=False,
            )
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit(
            "domain_event_emitted",
            {
                "event_id": record.event_id,
                "event_type": record.event_type,
                "source": record.source,
                "data_hash": record.data_hash,
            },
            redacted=False,
        )
        ctx.emit(
            "execution_completed",
            {"capability_id": emit_desc.id, "outcome": "success"},
            redacted=False,
        )
        return record.to_dict()

    host.register(emit_desc, _emit_event)

    # ── events.query ──────────────────────────────────────────────────────────

    query_desc = CapabilityDescriptor(
        id=f"{prefix}.query",
        version=version,
        description="Query stored domain events from the event bus.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["events"],
        emits=list(_QUERY_EMITS),
    )

    async def _query_events(ctx, payload) -> dict:
        event_type: str | None = payload.get("event_type")
        source: str | None = payload.get("source")
        limit: int | None = payload.get("limit")

        ctx.emit(
            "execution_started",
            {"capability_id": query_desc.id, "capability_version": version},
            redacted=False,
        )
        try:
            result = bus.query_events(event_type=event_type, source=source, limit=limit)
        except Exception as exc:
            ctx.emit(
                "domain_event_operation_failed",
                {"error": str(exc), "operation": "query"},
                redacted=False,
            )
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit(
            "domain_events_queried",
            {
                "event_type_filter": event_type,
                "source_filter": source,
                "event_count": result.event_count,
            },
            redacted=False,
        )
        ctx.emit(
            "execution_completed",
            {"capability_id": query_desc.id, "outcome": "success"},
            redacted=False,
        )
        return result.to_dict()

    host.register(query_desc, _query_events)
