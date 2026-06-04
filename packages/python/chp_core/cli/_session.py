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
