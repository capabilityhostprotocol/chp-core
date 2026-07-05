"""No-dependency OpenTelemetry export mapping helpers.

Span mapping functions (evidence_to_otel_span, replay_to_otel_spans) convert
CHP evidence events to OTLP-compatible span dicts. export_otlp_http sends them
to any OTLP HTTP collector using only stdlib urllib — no opentelemetry-sdk dep.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .types import JSON


def _hex_id(value: str | None, n_bytes: int) -> str:
    """Deterministic valid OTLP hex id (n_bytes → 2*n_bytes hex chars) from a CHP
    id. OTLP requires 16-byte trace ids and 8-byte span ids as hex — CHP's string
    ids (`inv_…`, `corr_…`) aren't valid, so we hash them into the required shape.
    Deterministic, so the same CHP id always maps to the same span/trace id."""
    if not value:
        return "0" * (2 * n_bytes)
    return hashlib.sha256(value.encode()).hexdigest()[: 2 * n_bytes]


def _unix_nano(ts: str | None) -> str:
    """ISO-8601 → nanoseconds-since-epoch string (OTLP time format)."""
    if not ts:
        return "0"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str(int(dt.timestamp() * 1_000_000_000))
    except ValueError:
        return "0"


def _gen_ai_attributes(capability_id: str) -> dict[str, Any]:
    """OTel GenAI semantic conventions for LLM/agent capabilities, so CHP evidence
    lands in GenAI-aware backends. Best-effort by capability id."""
    cid = capability_id.lower()
    if any(k in cid for k in ("llm", "chat", "generate", "completion", "gemini", "openai", "claude", "mlx")):
        return {"gen_ai.operation.name": "chat", "gen_ai.system": "chp"}
    return {}


def _governance_attributes(events: list[JSON]) -> dict[str, Any]:
    """Surface the governance decisions on an invocation as first-class, queryable
    span attributes — not only nested span events. This is CHP's differentiator
    carried into OTel: a backend can filter 'chp.safety.blocked = true' or
    'chp.approval.requested = true' the same way it filters chp.denied. The
    governance evidence rides the same span (same invocation_id)."""
    by_type: dict[str, JSON] = {e["event_type"]: (e.get("payload") or {}) for e in events}
    attrs: dict[str, Any] = {}

    # Safety: a signed assessment on every governed invocation, block or not.
    completed = by_type.get("safety_assessment_completed")
    if completed is not None:
        attrs["chp.safety.assessed"] = True
        if completed.get("level") is not None:
            attrs["chp.safety.level"] = completed["level"]
        if completed.get("score") is not None:
            attrs["chp.safety.score"] = completed["score"]
        attrs["chp.safety.blocked"] = "safety_action_blocked" in by_type

    # Autonomy budget.
    if "budget_exceeded" in by_type:
        attrs["chp.budget.exceeded"] = True

    # Human approval.
    if "approval_requested" in by_type:
        attrs["chp.approval.requested"] = True
        if "approval_granted" in by_type:
            attrs["chp.approval.decision"] = "granted"
        elif "approval_denied" in by_type:
            attrs["chp.approval.decision"] = "denied"

    return attrs


def evidence_to_otel_span(event: JSON) -> JSON:
    """Map one CHP evidence event to an OTLP-like span payload."""

    correlation = event.get("correlation") or {}
    causation_id = correlation.get("causation_id")
    return {
        "name": event["capability_id"],
        "trace_id": _hex_id(correlation.get("trace_id") or correlation.get("correlation_id"), 16),
        "span_id": _hex_id(event["invocation_id"], 8),
        "parent_span_id": _hex_id(causation_id, 8) if causation_id else None,
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

        causation_id = correlation.get("causation_id")
        # content_hash of the terminal event = this span's tamper-evident anchor.
        content_hash = last.get("content_hash") or first.get("content_hash")
        spans.append(
            {
                "name": first["capability_id"],
                # Valid OTLP: trace from correlation, span from invocation, and
                # parent from the causal edge (causation_id) → a real span tree.
                "trace_id": _hex_id(correlation.get("trace_id") or correlation.get("correlation_id"), 16),
                "span_id": _hex_id(invocation_id, 8),
                "parent_span_id": _hex_id(causation_id, 8) if causation_id else None,
                "start_time": _unix_nano(first["timestamp"]),
                "end_time": _unix_nano(last["timestamp"]),
                "attributes": {
                    "chp.host_id": first["host_id"],
                    "chp.capability_id": first["capability_id"],
                    "chp.capability_version": first.get("capability_version"),
                    "chp.invocation_id": invocation_id,
                    "chp.correlation_id": correlation.get("correlation_id"),
                    "chp.causation_id": causation_id,
                    "chp.outcome": last.get("outcome"),
                    # The CHP differentiators, carried into OTel: tamper-evidence…
                    "chp.content_hash": content_hash,
                    # …and denial as a first-class, queryable attribute.
                    "chp.denied": last.get("event_type") == "execution_denied",
                    "chp.denial_code": (last.get("denial") or {}).get("code") if last.get("denial") else None,
                    # …and the full governance decision surface, queryable.
                    **_governance_attributes(invocation_events),
                    **_gen_ai_attributes(first["capability_id"]),
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
                                **({"parentSpanId": span["parent_span_id"]}
                                   if span.get("parent_span_id") else {}),
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
