"""No-dependency OpenTelemetry export mapping helpers.

Span mapping functions (evidence_to_otel_span, replay_to_otel_spans) convert
CHP evidence events to OTLP-compatible span dicts. export_otlp_http sends them
to any OTLP HTTP collector using only stdlib urllib — no opentelemetry-sdk dep.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
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


def export_otlp_http(
    spans: list[JSON],
    *,
    endpoint: str = "http://localhost:4318/v1/traces",
    service_name: str = "chp",
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """POST spans to an OTLP HTTP collector.

    Uses only stdlib urllib — no opentelemetry-sdk required. The payload is
    wrapped in a minimal OTLP ResourceSpans envelope.

    Returns a dict with exported count, endpoint, and HTTP status code.
    Raises urllib.error.URLError on connection failure.
    """
    otlp_body = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service_name}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "chp", "version": "0.2"},
                        "spans": [
                            {
                                "traceId": span.get("trace_id", ""),
                                "spanId": span.get("span_id", ""),
                                "name": span.get("name", ""),
                                "startTimeUnixNano": span.get("start_time", ""),
                                "endTimeUnixNano": span.get("end_time", span.get("start_time", "")),
                                "attributes": [
                                    {"key": k, "value": {"stringValue": str(v)}}
                                    for k, v in (span.get("attributes") or {}).items()
                                    if v is not None
                                ],
                                "status": span.get("status", {"code": "UNSET"}),
                                "events": span.get("events", []),
                            }
                            for span in spans
                        ],
                    }
                ],
            }
        ]
    }

    body = json.dumps(otlp_body).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        status = resp.status

    return {"exported": len(spans), "endpoint": endpoint, "status": status}


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
