"""MCP tool schemas and handlers — thin wrappers over chp_inspector modules."""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

# Default evidence store (same as chp_inspector)
_DEFAULT_STORE = str(Path.home() / ".chp" / "claude-code-sessions.sqlite")


def _capture(fn, *args, **kwargs) -> str:
    """Call fn(*args, **kwargs) and return everything it prints."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue().strip()


# ── Tool schemas (MCP inputSchema format) ────────────────────────────────────

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "chp_sessions",
        "description": (
            "List recent CHP sessions recorded from Claude Code. "
            "Returns a table of session IDs, tool counts, and timestamps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max sessions to return (default: 20)"},
            },
        },
    },
    {
        "name": "chp_show",
        "description": (
            "Show a detailed summary of a single CHP session: duration, tool calls, "
            "files read/written, shell commands, failures, and chain integrity status."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "The session ID to inspect"},
            },
        },
    },
    {
        "name": "chp_tree",
        "description": (
            "Show the multi-agent session tree rooted at a session ID. "
            "Displays parent→child relationships and hash-chain integrity at every node."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "Root session ID"},
                "depth": {"type": "integer", "description": "Max tree depth (default: 10)"},
            },
        },
    },
    {
        "name": "chp_query",
        "description": (
            "Query the raw evidence store with optional filters. "
            "Returns a table of matching events: seq, type, capability, outcome, timestamp."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability_id": {"type": "string", "description": "Filter by capability ID"},
                "outcome": {"type": "string", "description": "Filter by outcome (success/failure/denied)"},
                "since": {"type": "string", "description": "ISO timestamp lower bound"},
                "limit": {"type": "integer", "description": "Max events to return"},
            },
        },
    },
    {
        "name": "chp_breakdown",
        "description": (
            "Show a per-capability breakdown of success/failure/denied counts "
            "across all recorded events. Useful for spotting problematic capabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO timestamp lower bound"},
            },
        },
    },
    {
        "name": "chp_verify",
        "description": (
            "Verify the SHA-256 hash chain for a session. "
            "Reports whether the evidence has been tampered with."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "The session ID to verify"},
            },
        },
    },
]


# ── Tool handlers ─────────────────────────────────────────────────────────────

def dispatch(tool_name: str, arguments: dict[str, Any], store_path: str) -> str:
    """Invoke the named tool and return its text output."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "python"))
    from tools.chp_inspector import (  # noqa: PLC0415  (nested import)
        query_view,
        session_view,
        tree_view,
    )

    if tool_name == "chp_sessions":
        limit = int(arguments.get("limit", 20))
        return _capture(session_view.list_sessions, store_path, limit=limit) or "No sessions found."

    if tool_name == "chp_show":
        return _capture(session_view.show_session, arguments["session_id"], store_path) or "No events found."

    if tool_name == "chp_tree":
        depth = int(arguments.get("depth", 10))
        return _capture(tree_view.render_tree, arguments["session_id"], store_path, depth=depth)

    if tool_name == "chp_query":
        return _capture(
            query_view.run_query,
            store_path,
            capability_id=arguments.get("capability_id"),
            outcome=arguments.get("outcome"),
            since=arguments.get("since"),
            limit=arguments.get("limit"),
        ) or "No events matched."

    if tool_name == "chp_breakdown":
        return _capture(query_view.capability_breakdown, store_path, since=arguments.get("since"))

    if tool_name == "chp_verify":
        buf = io.StringIO()
        with redirect_stdout(buf):
            session_view.verify_session(arguments["session_id"], store_path)
        return buf.getvalue().strip()

    return f"Unknown tool: {tool_name}"
