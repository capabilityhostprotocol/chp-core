"""Session listing, summary, and chain verification commands."""

from __future__ import annotations

import sys
from collections import defaultdict

_ANSI = sys.stdout.isatty()
_BOLD  = "\033[1m"  if _ANSI else ""
_GREEN = "\033[32m" if _ANSI else ""
_RED   = "\033[31m" if _ANSI else ""
_DIM   = "\033[2m"  if _ANSI else ""
_RESET = "\033[0m"  if _ANSI else ""

_FILE_TOOLS = {"Read", "Write", "Edit", "Glob", "Grep", "LS", "NotebookEdit"}


def list_sessions(store_path: str, limit: int = 20) -> None:
    """Print a table of recent sessions ordered by their session_completed event."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        # Session-completed events carry session_id, tool_count, and timestamp.
        events = store.query(capability_id="claude_code.session", limit=limit)
    finally:
        store.close()

    if not events:
        print("No sessions found. Is CHP hooks installed? Run: chp hooks install")
        return

    # Sort most-recent first (events come back oldest-first from query).
    events = list(reversed(events))

    print(f"\n{'SESSION ID':<36}  {'TOOLS':>5}  {'TIMESTAMP'}")
    print("-" * 72)
    for ev in events:
        sid   = (ev.get("correlation") or {}).get("correlation_id", "?")
        ts    = (ev.get("timestamp") or "")[:19].replace("T", " ")
        tools = (ev.get("payload") or {}).get("tool_count", "?")
        print(f"{sid:<36}  {str(tools):>5}  {ts}")


def show_session(session_id: str, store_path: str) -> None:
    """Detailed session summary: duration, tools, files, commands, failures."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(session_id)
        chain  = store.verify_chain(session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {session_id}")
        return

    # Derived stats
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    failures    = [e for e in events if e.get("outcome") == "failure"]
    denials     = [e for e in events if e.get("outcome") == "denied"]

    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
    duration_s: float | None = None
    if len(timestamps) >= 2:
        from datetime import datetime, timezone
        def _parse(ts: str) -> datetime:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        duration_s = (_parse(timestamps[-1]) - _parse(timestamps[0])).total_seconds()

    # Capability breakdown
    cap_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for ev in events:
        cap = ev.get("capability_id") or ""
        outcome = ev.get("outcome") or ev.get("event_type") or ""
        cap_counts[cap][outcome] += 1

    # Files touched
    files_read:    list[str] = []
    files_written: list[str] = []
    commands:      list[str] = []
    for ev in tool_events:
        inp = ev.get("payload", {}).get("tool_input") or {}
        tool = ev.get("payload", {}).get("tool_name") or ""
        if tool in ("Read", "Glob", "Grep"):
            path = inp.get("file_path") or inp.get("pattern") or ""
            if path:
                files_read.append(path)
        elif tool in ("Write", "Edit", "NotebookEdit"):
            path = inp.get("file_path") or ""
            if path:
                files_written.append(path)
        elif tool == "Bash":
            cmd = inp.get("command") or ""
            if cmd:
                commands.append(cmd[:80])

    chain_status = (
        f"{_GREEN}chain:ok{_RESET}" if chain.valid
        else f"{_RED}chain:BROKEN at seq {chain.first_broken_sequence}{_RESET}"
    )
    parent = None
    for ev in events:
        p = (ev.get("correlation") or {}).get("parent_correlation_id")
        if p:
            parent = p
            break

    print(f"\n{_BOLD}Session: {session_id}{_RESET}")
    if parent:
        print(f"  Parent:    {parent}")
    print(f"  Events:    {len(events)}")
    print(f"  Tool calls:{len(tool_events)}")
    if duration_s is not None:
        print(f"  Duration:  {duration_s:.1f}s")
    print(f"  Integrity: {chain_status}")
    if failures:
        print(f"  {_RED}Failures:  {len(failures)}{_RESET}  → {[e.get('capability_id') for e in failures]}")
    if denials:
        print(f"  {_RED}Denied:    {len(denials)}{_RESET}  → {[e.get('capability_id') for e in denials]}")

    if files_written:
        print(f"\n  Files written ({len(files_written)}):")
        for f in dict.fromkeys(files_written):
            print(f"    {f}")
    if commands:
        print(f"\n  Shell commands ({len(commands)}):")
        for c in commands[:10]:
            print(f"    $ {c}")
        if len(commands) > 10:
            print(f"    … and {len(commands) - 10} more")

    print(f"\n  {_DIM}Capability breakdown:{_RESET}")
    for cap, outcomes in sorted(cap_counts.items()):
        if not cap:
            continue
        summary = "  ".join(f"{k}={v}" for k, v in sorted(outcomes.items()))
        print(f"    {cap:<40} {summary}")


def verify_session(session_id: str, store_path: str) -> int:
    """Verify hash chain and print result. Returns 0 if valid, 1 if broken."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        result = store.verify_chain(session_id)
    finally:
        store.close()

    if result.valid:
        print(f"{_GREEN}chain:ok{_RESET}  {session_id}  ({result.event_count} events verified)")
        return 0
    else:
        print(
            f"{_RED}chain:BROKEN{_RESET}  {session_id}  "
            f"first broken at sequence {result.first_broken_sequence}"
        )
        return 1
