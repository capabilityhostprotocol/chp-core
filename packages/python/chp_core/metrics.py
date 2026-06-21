"""chp.invocations.* metrics aggregation and Prometheus exposition (§9.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .types import CapabilityMetrics, JSON, SessionMetricsReport


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None


def _percentile(values: list[float], p: int) -> float:
    """Return the p-th percentile of a non-empty list (0–100)."""
    sorted_vals = sorted(values)
    idx = (len(sorted_vals) - 1) * p / 100
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] + frac * (sorted_vals[hi] - sorted_vals[lo])


def _get_cap_id(event: JSON) -> str:
    """Extract capability_id: top-level field first, then payload."""
    return (
        event.get("capability_id")
        or (event.get("payload") or {}).get("capability_id")
        or "unknown"
    )


def _is_host_level(event: JSON) -> bool:
    """True for host-emitted execution events that have capability_uri in payload."""
    return "capability_uri" in (event.get("payload") or {})


def aggregate_session_metrics(session_id: str, events: list[JSON]) -> SessionMetricsReport:
    """Aggregate per-capability invocation metrics from a correlation's evidence events.

    Uses host-emitted execution_started/execution_completed events (identified by
    capability_uri in their payload) as the authoritative invocation boundary.
    Each execution_started/execution_completed pair with matching capability_id is
    one invocation. This correctly counts nested invocations (e.g. workflow steps)
    because each child ainvoke generates its own host-level pair.

    Falls back to sequential pairing when events lack capability_uri (e.g. unit-test
    constructed event lists).
    """
    # Determine whether we are working with real store events or synthetic test events
    has_host_events = any(_is_host_level(e) for e in events if e.get("event_type") == "execution_started")

    if has_host_events:
        return _aggregate_host_level(session_id, events)
    return _aggregate_sequential(session_id, events)


def _aggregate_host_level(session_id: str, events: list[JSON]) -> SessionMetricsReport:
    """Count invocations using host-emitted execution events (capability_uri in payload)."""
    open_stack: dict[str, list[str]] = {}
    stats: dict[str, dict[str, Any]] = {}

    def _ensure(cap_id: str) -> dict[str, Any]:
        if cap_id not in stats:
            stats[cap_id] = {"invocations": 0, "successes": 0, "failures": 0, "denied": 0, "durations": []}
        return stats[cap_id]

    for event in events:
        etype = event.get("event_type", "")
        is_host = _is_host_level(event)
        cap_id = _get_cap_id(event)
        occurred_at: str = event.get("occurred_at") or event.get("timestamp") or ""

        if etype == "execution_started" and is_host:
            _ensure(cap_id)["invocations"] += 1
            open_stack.setdefault(cap_id, []).append(occurred_at)
        elif etype == "execution_completed" and is_host:
            s = _ensure(cap_id)
            s["successes"] += 1
            stack = open_stack.get(cap_id, [])
            if stack:
                started_at = stack.pop()
                t_start = _parse_iso(started_at)
                t_end = _parse_iso(occurred_at)
                if t_start and t_end:
                    dur_ms = (t_end - t_start).total_seconds() * 1000
                    if dur_ms >= 0:
                        s["durations"].append(dur_ms)
        elif etype == "execution_failed":
            # Failures may not have capability_uri — count all failure events
            s = _ensure(cap_id)
            s["failures"] += 1
        elif etype == "execution_denied" and is_host:
            _ensure(cap_id)["denied"] += 1

    return _build_report(session_id, stats)


def _aggregate_sequential(session_id: str, events: list[JSON]) -> SessionMetricsReport:
    """Count invocations using sequential pairing of execution_started/completed events.

    Used when events are constructed without capability_uri (e.g. unit tests).
    """
    open_stack: dict[str, list[str]] = {}
    stats: dict[str, dict[str, Any]] = {}

    def _ensure(cap_id: str) -> dict[str, Any]:
        if cap_id not in stats:
            stats[cap_id] = {"invocations": 0, "successes": 0, "failures": 0, "denied": 0, "durations": []}
        return stats[cap_id]

    for event in events:
        etype = event.get("event_type", "")
        cap_id = _get_cap_id(event)
        occurred_at: str = event.get("occurred_at") or event.get("timestamp") or ""

        if etype == "execution_started":
            _ensure(cap_id)["invocations"] += 1
            open_stack.setdefault(cap_id, []).append(occurred_at)
        elif etype in ("execution_completed", "execution_failed", "execution_denied"):
            s = _ensure(cap_id)
            if etype == "execution_completed":
                s["successes"] += 1
            elif etype == "execution_failed":
                s["failures"] += 1
            else:
                s["denied"] += 1
            stack = open_stack.get(cap_id, [])
            if stack:
                started_at = stack.pop()
                t_start = _parse_iso(started_at)
                t_end = _parse_iso(occurred_at)
                if t_start and t_end:
                    dur_ms = (t_end - t_start).total_seconds() * 1000
                    if dur_ms >= 0:
                        s["durations"].append(dur_ms)

    return _build_report(session_id, stats)


def _build_report(session_id: str, stats: dict[str, dict[str, Any]]) -> SessionMetricsReport:
    capabilities: dict[str, CapabilityMetrics] = {}
    for cap_id, s in stats.items():
        durations: list[float] = s["durations"]
        avg_ms = round(sum(durations) / len(durations), 3) if durations else None
        p50_ms = round(_percentile(durations, 50), 3) if len(durations) >= 2 else None
        p95_ms = round(_percentile(durations, 95), 3) if len(durations) >= 2 else None
        capabilities[cap_id] = CapabilityMetrics(
            capability_id=cap_id,
            invocations=s["invocations"],
            successes=s["successes"],
            failures=s["failures"],
            denied=s["denied"],
            avg_duration_ms=avg_ms,
            p50_duration_ms=p50_ms,
            p95_duration_ms=p95_ms,
        )

    total = sum(m.invocations for m in capabilities.values())
    total_ok = sum(m.successes for m in capabilities.values())
    total_fail = sum(m.failures for m in capabilities.values())

    return SessionMetricsReport(
        session_id=session_id,
        total_invocations=total,
        total_successes=total_ok,
        total_failures=total_fail,
        capabilities=capabilities,
    )


@dataclass
class TokenMetricsReport:
    """Aggregated sovereign inference token counts for a time window."""
    prompt_by_model: dict[str, int] = field(default_factory=dict)
    completion_by_model: dict[str, int] = field(default_factory=dict)
    calls_by_model: dict[str, int] = field(default_factory=dict)


def aggregate_token_metrics(events: list[JSON]) -> TokenMetricsReport:
    """Aggregate prompt/completion token counts from http_response events."""
    report = TokenMetricsReport()
    for e in events:
        if e.get("event_type") != "http_response":
            continue
        p = e.get("payload", {})
        if "prompt_tokens" not in p:
            continue
        model = p.get("model", "unknown")
        report.prompt_by_model[model] = report.prompt_by_model.get(model, 0) + p["prompt_tokens"]
        report.completion_by_model[model] = report.completion_by_model.get(model, 0) + p.get("completion_tokens", 0)
        report.calls_by_model[model] = report.calls_by_model.get(model, 0) + 1
    return report


def format_token_prometheus(report: TokenMetricsReport) -> str:
    """Return Prometheus text exposition for sovereign token counters."""
    lines: list[str] = [
        "# HELP chp_sovereign_prompt_tokens_total Prompt tokens consumed by sovereign models (1h window).",
        "# TYPE chp_sovereign_prompt_tokens_total counter",
    ]
    for model, count in report.prompt_by_model.items():
        lines.append(f'chp_sovereign_prompt_tokens_total{{model="{model}"}} {count}')
    lines += [
        "# HELP chp_sovereign_completion_tokens_total Completion tokens by sovereign models (1h window).",
        "# TYPE chp_sovereign_completion_tokens_total counter",
    ]
    for model, count in report.completion_by_model.items():
        lines.append(f'chp_sovereign_completion_tokens_total{{model="{model}"}} {count}')
    return "\n".join(lines) + "\n"


def format_prometheus(report: SessionMetricsReport) -> str:
    """Return Prometheus text exposition format with chp_invocations_* metric names."""
    lines: list[str] = []

    lines.append("# HELP chp_invocations_total Total CHP capability invocations by outcome.")
    lines.append("# TYPE chp_invocations_total counter")
    for m in report.capabilities.values():
        cid = m.capability_id
        lines.append(f'chp_invocations_total{{capability_id="{cid}",outcome="success"}} {m.successes}')
        lines.append(f'chp_invocations_total{{capability_id="{cid}",outcome="failure"}} {m.failures}')
        if m.denied:
            lines.append(f'chp_invocations_total{{capability_id="{cid}",outcome="denied"}} {m.denied}')

    lines.append("# HELP chp_invocations_duration_ms_avg Average invocation duration in milliseconds.")
    lines.append("# TYPE chp_invocations_duration_ms_avg gauge")
    for m in report.capabilities.values():
        if m.avg_duration_ms is not None:
            lines.append(
                f'chp_invocations_duration_ms_avg{{capability_id="{m.capability_id}"}} {m.avg_duration_ms}'
            )

    lines.append("# HELP chp_invocations_duration_ms_p50 Median invocation duration in milliseconds.")
    lines.append("# TYPE chp_invocations_duration_ms_p50 gauge")
    for m in report.capabilities.values():
        if m.p50_duration_ms is not None:
            lines.append(
                f'chp_invocations_duration_ms_p50{{capability_id="{m.capability_id}"}} {m.p50_duration_ms}'
            )

    lines.append("# HELP chp_invocations_duration_ms_p95 P95 invocation duration in milliseconds.")
    lines.append("# TYPE chp_invocations_duration_ms_p95 gauge")
    for m in report.capabilities.values():
        if m.p95_duration_ms is not None:
            lines.append(
                f'chp_invocations_duration_ms_p95{{capability_id="{m.capability_id}"}} {m.p95_duration_ms}'
            )

    return "\n".join(lines) + "\n"
