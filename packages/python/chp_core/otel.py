"""No-dependency OpenTelemetry export mapping helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .types import JSON


def evidence_to_otel_span(event: JSON) -> JSON:
    """Map one CHP evidence event to an OTLP-like span payload."""

    correlation = event.get("correlation") or {}
    return {
        "name": event["capability_id"],
        "trace_id": correlation.get("trace_id") or correlation.get("correlation_id"),
        "span_id": event["invocation_id"],
        "attributes": {
            "chp.host_id": event["host_id"],
            "chp.capability_id": event["capability_id"],
            "chp.capability_version": event.get("capability_version"),
            "chp.invocation_id": event["invocation_id"],
            "chp.correlation_id": correlation.get("correlation_id"),
            "chp.event_id": event["event_id"],
            "chp.event_type": event["event_type"],
            "chp.outcome": event.get("outcome"),
            "chp.sequence": event.get("sequence"),
        },
        "events": [
            {
                "name": event["event_type"],
                "time": event["timestamp"],
                "attributes": _flatten_payload("chp.payload", event.get("payload") or {}),
            }
        ],
        "status": _status_for_outcome(event.get("outcome")),
    }


def replay_to_otel_spans(events: list[JSON]) -> list[JSON]:
    """Group replayed CHP events into OTLP-like spans by invocation ID."""

    grouped: dict[str, list[JSON]] = defaultdict(list)
    for event in events:
        grouped[event["invocation_id"]].append(event)

    spans: list[JSON] = []
    for invocation_id, invocation_events in grouped.items():
        first = invocation_events[0]
        last = invocation_events[-1]
        correlation = first.get("correlation") or {}
        span_events = [
            {
                "name": event["event_type"],
                "time": event["timestamp"],
                "attributes": {
                    "chp.event_id": event["event_id"],
                    "chp.sequence": event["sequence"],
                    **_flatten_payload("chp.payload", event.get("payload") or {}),
                },
            }
            for event in invocation_events
        ]

        spans.append(
            {
                "name": first["capability_id"],
                "trace_id": correlation.get("trace_id") or correlation.get("correlation_id"),
                "span_id": invocation_id,
                "start_time": first["timestamp"],
                "end_time": last["timestamp"],
                "attributes": {
                    "chp.host_id": first["host_id"],
                    "chp.capability_id": first["capability_id"],
                    "chp.capability_version": first.get("capability_version"),
                    "chp.invocation_id": invocation_id,
                    "chp.correlation_id": correlation.get("correlation_id"),
                    "chp.outcome": last.get("outcome"),
                },
                "events": span_events,
                "status": _status_for_outcome(last.get("outcome")),
            }
        )

    return spans


def _flatten_payload(prefix: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {prefix: payload}

    flattened: dict[str, Any] = {}
    for key, value in payload.items():
        name = f"{prefix}.{key}"
        if isinstance(value, dict):
            flattened.update(_flatten_payload(name, value))
        elif isinstance(value, (str, int, float, bool)) or value is None:
            flattened[name] = value
        else:
            flattened[name] = str(value)
    return flattened


def _status_for_outcome(outcome: str | None) -> JSON:
    if outcome == "success":
        return {"code": "OK"}
    if outcome == "failure":
        return {"code": "ERROR"}
    return {"code": "UNSET"}
