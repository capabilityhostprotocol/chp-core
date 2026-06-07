"""CHP CLI session query, replay, and export commands."""

from __future__ import annotations

import argparse
import json
from typing import Any

from ._core import _resolve_store, print_json


_FILE_TOOLS = {
    "claude_code.read", "claude_code.edit", "claude_code.write",
    "claude_code.grep", "claude_code.glob",
}


def cmd_session_list(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.query(capability_id="claude_code.session", limit=args.limit)
    finally:
        store.close()

    if not events:
        print("No sessions found.")
        return 0

    print_json(events)
    return 0


def cmd_session_replay(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}")
        return 1

    print_json(events)
    return 0


def cmd_session_show(args: argparse.Namespace) -> int:
    from collections import Counter

    from ..store import SQLiteEvidenceStore
    from ..types import JSON

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}")
        return 1

    tool_events = [e for e in events if e.get("event_type") == "tool_use"]
    requested_events = [e for e in events if e.get("event_type") == "tool_use_requested"]
    session_ev = next((e for e in events if e.get("event_type") == "session_completed"), None)
    failures = [e for e in tool_events if e.get("outcome") == "failure"]

    files_touched: set[str] = set()
    commands_run: list[dict[str, Any]] = []
    for event in tool_events:
        cap_id = event.get("capability_id", "")
        inp = event.get("payload", {}).get("tool_input", {}) or {}
        if cap_id in _FILE_TOOLS:
            for key in ("file_path", "path", "pattern"):
                if val := inp.get(key):
                    files_touched.add(val)
        if cap_id == "claude_code.bash":
            commands_run.append({
                "command": (inp.get("command") or "")[:120],
                "outcome": event.get("outcome"),
            })

    timestamps: list[str] = [t for e in events if (t := e.get("timestamp")) and isinstance(t, str)]
    duration_seconds: float | None = None
    if len(timestamps) >= 2:
        try:
            from datetime import datetime
            t0 = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
            duration_seconds = round((t1 - t0).total_seconds(), 1)
        except Exception:  # noqa: BLE001
            pass

    tool_counts: Counter[str] = Counter(str(e["capability_id"]) for e in tool_events if e.get("capability_id"))
    summary: JSON = {
        "session_id": args.session_id,
        "tool_count": len(tool_events),
        "requested_count": len(requested_events),
        "failure_count": len(failures),
        "duration_seconds": duration_seconds,
        "tools_used": dict(tool_counts.most_common()),
        "files_touched": sorted(files_touched),
        "commands_run": commands_run,
        "failures": [
            {"capability_id": e.get("capability_id"), "timestamp": e.get("timestamp")}
            for e in failures
        ],
    }
    if session_ev:
        summary["transcript_path"] = session_ev.get("payload", {}).get("transcript_path", "")

    print_json(summary)
    return 0


def _build_session_node(
    session_id: str,
    store_path: str,
    depth: int,
    visited: set[str],
) -> dict[str, Any]:
    """Recursively build a session tree node."""
    from ..store import SQLiteEvidenceStore

    if depth <= 0 or session_id in visited:
        return {"session_id": session_id, "truncated": True, "children": []}

    visited.add(session_id)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(session_id)
        children_ids = store.children_of(session_id)
    finally:
        store.close()

    tool_events = [e for e in events if e.get("event_type") == "tool_use"]
    requested_events = [e for e in events if e.get("event_type") == "tool_use_requested"]

    children = [
        _build_session_node(child_id, store_path, depth - 1, visited)
        for child_id in children_ids
    ]
    return {
        "session_id": session_id,
        "tool_count": len(tool_events),
        "requested_count": len(requested_events),
        "child_count": len(children),
        "children": children,
    }


def cmd_session_tree(args: argparse.Namespace) -> int:
    store_path = _resolve_store(args.store)
    visited: set[str] = set()
    tree = _build_session_node(args.session_id, store_path, args.depth, visited)
    print_json(tree)
    return 0


def cmd_session_otel(args: argparse.Namespace) -> int:
    import sys
    from ..otel import export_otlp_http, replay_to_otel_spans
    from ..store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}", file=sys.stderr)
        return 1

    spans = replay_to_otel_spans(events)

    if args.dry_run:
        print(json.dumps(spans, indent=2))
        return 0

    try:
        result = export_otlp_http(spans, endpoint=args.endpoint)
        print(json.dumps(result))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"OTLP export failed: {exc}", file=sys.stderr)
        return 1


def cmd_session_autonomy_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import AUTONOMY_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    autonomy_events = [e for e in events if e.get("event_type") in AUTONOMY_EVIDENCE_TYPES]

    # Classify approval_requested events as pending or resolved
    resolved_caps: set[str] = set()
    for ev in autonomy_events:
        if ev.get("event_type") in ("approval_granted", "approval_denied"):
            cap = (ev.get("payload") or {}).get("capability_uri", ev.get("capability_id", ""))
            resolved_caps.add(cap)

    pending_approvals = [
        ev for ev in autonomy_events
        if ev.get("event_type") == "approval_requested"
        and (ev.get("payload") or {}).get("capability_uri", ev.get("capability_id", "")) not in resolved_caps
    ]

    print_json({
        "session_id": args.session_id,
        "autonomy_event_count": len(autonomy_events),
        "pending_approvals": len(pending_approvals),
        "events": autonomy_events,
    })
    return 0 if autonomy_events else 1


def cmd_session_retrieval_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import RETRIEVAL_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    retrieval_events = [e for e in events if e.get("event_type") in RETRIEVAL_EVIDENCE_TYPES]
    completed = [e for e in retrieval_events if e.get("event_type") == "retrieval_completed"]

    total_results = sum((e.get("payload") or {}).get("result_count", 0) for e in completed)
    latencies = [
        (e.get("payload") or {}).get("latency_ms")
        for e in completed
        if (e.get("payload") or {}).get("latency_ms") is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    print_json({
        "session_id": args.session_id,
        "retrieval_event_count": len(retrieval_events),
        "retrieval_calls": len(completed),
        "total_results_returned": total_results,
        "avg_latency_ms": avg_latency,
        "events": retrieval_events,
    })
    return 0 if retrieval_events else 1


def cmd_session_ingestion_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import INGESTION_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    ingestion_events = [e for e in events if e.get("event_type") in INGESTION_EVIDENCE_TYPES]
    completed = [e for e in ingestion_events if e.get("event_type") == "ingestion_completed"]

    total_records = sum((e.get("payload") or {}).get("record_count", 0) for e in completed)
    total_bytes = sum((e.get("payload") or {}).get("total_bytes", 0) for e in completed)
    latencies = [
        (e.get("payload") or {}).get("latency_ms")
        for e in completed
        if (e.get("payload") or {}).get("latency_ms") is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    print_json({
        "session_id": args.session_id,
        "ingestion_event_count": len(ingestion_events),
        "ingestion_calls": len(completed),
        "total_records_ingested": total_records,
        "total_bytes_ingested": total_bytes,
        "avg_latency_ms": avg_latency,
        "events": ingestion_events,
    })
    return 0 if ingestion_events else 1


def cmd_session_transformation_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import TRANSFORMATION_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    transformation_events = [e for e in events if e.get("event_type") in TRANSFORMATION_EVIDENCE_TYPES]
    completed = [e for e in transformation_events if e.get("event_type") == "transformation_completed"]

    transforms_by_type: dict[str, int] = {}
    for e in completed:
        t = (e.get("payload") or {}).get("transform_type", "unknown")
        transforms_by_type[t] = transforms_by_type.get(t, 0) + 1

    latencies = [
        (e.get("payload") or {}).get("latency_ms")
        for e in completed
        if (e.get("payload") or {}).get("latency_ms") is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    print_json({
        "session_id": args.session_id,
        "transformation_event_count": len(transformation_events),
        "transformation_calls": len(completed),
        "transforms_by_type": transforms_by_type,
        "avg_latency_ms": avg_latency,
        "events": transformation_events,
    })
    return 0 if transformation_events else 1


def cmd_session_workflow_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import WORKFLOW_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    workflow_events = [e for e in events if e.get("event_type") in WORKFLOW_EVIDENCE_TYPES]
    completed = [e for e in workflow_events if e.get("event_type") == "workflow_completed"]
    step_completed = [e for e in workflow_events if e.get("event_type") == "workflow_step_completed"]
    step_failed = [e for e in workflow_events if e.get("event_type") == "workflow_step_failed"]

    latencies = [
        (e.get("payload") or {}).get("total_duration_ms")
        for e in completed
        if (e.get("payload") or {}).get("total_duration_ms") is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    print_json({
        "session_id": args.session_id,
        "workflow_event_count": len(workflow_events),
        "workflows_run": len(completed),
        "steps_completed": len(step_completed),
        "steps_failed": len(step_failed),
        "avg_workflow_duration_ms": avg_latency,
        "events": workflow_events,
    })
    return 0 if workflow_events else 1


def cmd_session_events_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import DOMAIN_EVENT_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    domain_events = [e for e in events if e.get("event_type") in DOMAIN_EVENT_EVIDENCE_TYPES]
    emitted = [e for e in domain_events if e.get("event_type") == "domain_event_emitted"]
    queried = [e for e in domain_events if e.get("event_type") == "domain_events_queried"]

    events_by_type: dict[str, int] = {}
    for e in emitted:
        t = (e.get("payload") or {}).get("event_type", "unknown")
        events_by_type[t] = events_by_type.get(t, 0) + 1

    print_json({
        "session_id": args.session_id,
        "domain_event_count": len(domain_events),
        "events_emitted": len(emitted),
        "events_queried": len(queried),
        "events_by_type": events_by_type,
        "events": domain_events,
    })
    return 0 if domain_events else 1


def cmd_session_graph_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..types import GRAPH_EVIDENCE_TYPES

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    graph_events = [e for e in events if e.get("event_type") in GRAPH_EVIDENCE_TYPES]
    entities_added = len([e for e in graph_events if e.get("event_type") == "graph_entity_added"])
    relations_added = len([e for e in graph_events if e.get("event_type") == "graph_relation_added"])
    queries = len([e for e in graph_events if e.get("event_type") == "graph_queried"])
    traversals = len([e for e in graph_events if e.get("event_type") == "graph_traversed"])

    query_events = [e for e in graph_events if e.get("event_type") in {"graph_queried", "graph_traversed"}]
    latencies = [
        (e.get("payload") or {}).get("latency_ms")
        for e in query_events
        if (e.get("payload") or {}).get("latency_ms") is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    print_json({
        "session_id": args.session_id,
        "graph_event_count": len(graph_events),
        "entities_added": entities_added,
        "relations_added": relations_added,
        "queries": queries,
        "traversals": traversals,
        "avg_query_latency_ms": avg_latency,
        "events": graph_events,
    })
    return 0 if graph_events else 1


def cmd_session_metrics_report(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore
    from ..metrics import aggregate_session_metrics, format_prometheus

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    report = aggregate_session_metrics(args.session_id, events)

    if getattr(args, "format", "json") == "prometheus":
        print(format_prometheus(report), end="")
    else:
        print_json(report.to_dict())

    return 0 if report.total_invocations > 0 else 1


def cmd_session_export(args: argparse.Namespace) -> int:
    import sys
    from ..store import SQLiteEvidenceStore
    from ..types import utc_now

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation_with_hashes(args.session_id)
        chain = store.verify_chain(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}", file=sys.stderr)
        return 1

    hashes_included = any("content_hash" in e for e in events)
    bundle = {
        "format": "chp-session-bundle/1",
        "session_id": args.session_id,
        "exported_at": utc_now(),
        "event_count": len(events),
        "hashes_included": hashes_included,
        "chain_valid": chain.valid if hashes_included else None,
        "events": events,
    }

    output = json.dumps(bundle, indent=2, sort_keys=True)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(output)
        print(f"Exported {len(events)} events to {args.output}")
    else:
        print(output)
    return 0
