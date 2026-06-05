"""JSON-RPC 2.0 stdio MCP server for CHP evidence querying.

Implements the minimum MCP surface needed for Claude Code tool use:
  initialize / tools/list / tools/call

No external dependencies — pure stdlib JSON-RPC over stdin/stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .tools import TOOL_SCHEMAS, dispatch

_DEFAULT_STORE = str(Path.home() / ".chp" / "claude-code-sessions.sqlite")
_PROTOCOL_VERSION = "2024-11-05"


def _send(obj: dict) -> None:
    """Write a single JSON-RPC response line to stdout."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def run(store_path: str) -> None:
    """Read newline-delimited JSON-RPC messages from stdin; write responses to stdout."""
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue

        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
            continue

        mid = msg.get("id")
        method = msg.get("method", "")

        # Notifications (no id) — acknowledge silently
        if mid is None:
            continue

        if method == "initialize":
            _send({
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "chp", "version": __version__},
                },
            })

        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOL_SCHEMAS}})

        elif method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}
            try:
                text = dispatch(tool_name, arguments, store_path)
                _send({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"content": [{"type": "text", "text": text}]},
                })
            except Exception as exc:  # noqa: BLE001
                _send(_error(mid, -32603, f"Tool error: {exc}"))

        elif method == "ping":
            _send({"jsonrpc": "2.0", "id": mid, "result": {}})

        else:
            _send(_error(mid, -32601, f"Method not found: {method}"))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.chp_mcp",
        description="CHP MCP server — expose session evidence as Claude Code tools.",
    )
    parser.add_argument(
        "--store",
        default=_DEFAULT_STORE,
        metavar="PATH",
        help=f"SQLite evidence store (default: {_DEFAULT_STORE})",
    )
    args = parser.parse_args()
    run(args.store)
    return 0
