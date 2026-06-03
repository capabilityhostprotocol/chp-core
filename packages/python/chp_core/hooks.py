"""Claude Code hook processing for CHP v0.2.1.

Reads Claude Code hook JSON from stdin and emits evidence directly to a
SQLiteEvidenceStore — bypassing LocalCapabilityHost.invoke() for speed.
Each write must complete in < 5ms so the hook doesn't slow down the agent.

Usage (via chp CLI):
    echo '<PostToolUse JSON>' | chp hook post-tool
    echo '<Stop JSON>'        | chp hook stop

Environment:
    CHP_HOOK_STORE  Override the evidence store path (default: .chp/claude-code-sessions.sqlite
                    falling back to ~/.chp/sessions.sqlite when cwd has no .chp/ dir).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .redaction import redact_payload
from .store import SQLiteEvidenceStore
from .types import AssuranceMetadata, CorrelationContext, ExecutionEvidence, new_id, utc_now

_HOOK_HOST_ID = "claude-code"
_CAPABILITY_VERSION = "1.0.0"

# Maps Claude Code built-in tool names to CHP capability IDs.
TOOL_CAPABILITY_MAP: dict[str, str] = {
    "Bash": "claude_code.bash",
    "Read": "claude_code.read",
    "Edit": "claude_code.edit",
    "Write": "claude_code.write",
    "Grep": "claude_code.grep",
    "Glob": "claude_code.glob",
    "LS": "claude_code.ls",
    "WebFetch": "claude_code.web_fetch",
    "WebSearch": "claude_code.web_search",
    "Agent": "claude_code.agent",
    "Task": "claude_code.agent",
    "TodoRead": "claude_code.todo_read",
    "TodoWrite": "claude_code.todo_write",
    "NotebookRead": "claude_code.notebook_read",
    "NotebookEdit": "claude_code.notebook_edit",
    "mcp__memory__create_entities": "claude_code.mcp.memory.create_entities",
}


def capability_id_for_tool(tool_name: str) -> str:
    """Map a Claude Code tool name to a CHP capability ID."""
    if tool_name in TOOL_CAPABILITY_MAP:
        return TOOL_CAPABILITY_MAP[tool_name]
    # mcp__<server>__<tool> → claude_code.mcp.<server>.<tool>
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        server = parts[1] if len(parts) > 1 else "unknown"
        tool = parts[2].replace("__", ".") if len(parts) > 2 else "unknown"
        return f"claude_code.mcp.{server}.{tool}"
    # Anything else → claude_code.tool.<name>
    return f"claude_code.tool.{tool_name.lower()}"


def default_store_path() -> str:
    """Resolve the evidence store path using the env var or directory fallback."""
    env = os.environ.get("CHP_HOOK_STORE")
    if env:
        return env
    local = Path(".chp") / "claude-code-sessions.sqlite"
    if local.parent.exists() or _writable(local.parent.parent):
        return str(local)
    global_dir = Path.home() / ".chp"
    global_dir.mkdir(parents=True, exist_ok=True)
    return str(global_dir / "sessions.sqlite")


def _writable(path: Path) -> bool:
    return os.access(path, os.W_OK)


def _tool_output_preview(tool_response: Any, max_chars: int = 512) -> str:
    """Extract a short text preview from the tool response."""
    if isinstance(tool_response, dict):
        for key in ("output", "content", "result", "text"):
            val = tool_response.get(key)
            if isinstance(val, str) and val:
                return val[:max_chars]
        return str(tool_response)[:max_chars]
    if isinstance(tool_response, str):
        return tool_response[:max_chars]
    return ""


def _outcome_from_response(tool_response: Any) -> str:
    """Determine outcome from a PostToolUse tool_response."""
    if isinstance(tool_response, dict):
        if tool_response.get("error") or tool_response.get("interrupted"):
            return "failure"
        # Bash exit code
        if tool_response.get("exit_code", 0) not in (0, None):
            return "failure"
    return "success"


def process_post_tool_use(payload: dict[str, Any], store_path: str) -> None:
    """Emit a tool_use evidence event from a PostToolUse hook payload."""
    session_id = payload.get("session_id", "unknown-session")
    tool_name = payload.get("tool_name", "unknown")
    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response") or {}
    cwd = payload.get("cwd", "")

    cap_id = capability_id_for_tool(tool_name)
    outcome = _outcome_from_response(tool_response)

    event_payload = redact_payload({
        "tool_name": tool_name,
        "cwd": cwd,
        "tool_input": tool_input,
        "tool_output_preview": _tool_output_preview(tool_response),
        "exit_code": tool_response.get("exit_code") if isinstance(tool_response, dict) else None,
    })

    _append_event(
        store_path=store_path,
        event_type="tool_use",
        capability_id=cap_id,
        session_id=session_id,
        outcome=outcome,
        payload=event_payload,
    )


def process_stop(payload: dict[str, Any], store_path: str) -> None:
    """Emit a session_completed evidence event from a Stop hook payload."""
    session_id = payload.get("session_id", "unknown-session")
    transcript_path = payload.get("transcript_path", "")

    store = SQLiteEvidenceStore(store_path)
    try:
        tool_count = store.count_by_correlation(session_id)
    finally:
        store.close()

    _append_event(
        store_path=store_path,
        event_type="session_completed",
        capability_id="claude_code.session",
        session_id=session_id,
        outcome="success",
        payload={
            "tool_count": tool_count,
            "transcript_path": transcript_path,
        },
    )


def _append_event(
    *,
    store_path: str,
    event_type: str,
    capability_id: str,
    session_id: str,
    outcome: str,
    payload: dict[str, Any],
) -> None:
    store = SQLiteEvidenceStore(store_path)
    try:
        event = ExecutionEvidence(
            event_id=new_id("evt"),
            event_type=event_type,
            invocation_id=new_id("inv"),
            capability_id=capability_id,
            capability_version=_CAPABILITY_VERSION,
            host_id=_HOOK_HOST_ID,
            correlation=CorrelationContext(correlation_id=session_id),
            timestamp=utc_now(),
            outcome=outcome,  # type: ignore[arg-type]
            payload=payload,
            redacted=True,
            assurance=AssuranceMetadata(),
        )
        store.append(event)
    finally:
        store.close()
