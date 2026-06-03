"""Tests for v0.2.4 agent adapters: Codex CLI and Gemini CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from chp_core.hooks import (
    CODEX_TOOL_CAPABILITY_MAP,
    GEMINI_TOOL_CAPABILITY_MAP,
    capability_id_for_tool,
    process_post_tool_use,
    process_stop,
)
from chp_core.store import SQLiteEvidenceStore

_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


# ---------------------------------------------------------------------------
# capability_id_for_tool with custom maps
# ---------------------------------------------------------------------------

def test_capability_id_default_map_unchanged() -> None:
    assert capability_id_for_tool("Bash") == "claude_code.bash"
    assert capability_id_for_tool("Read") == "claude_code.read"


def test_capability_id_with_codex_map() -> None:
    assert capability_id_for_tool("shell", CODEX_TOOL_CAPABILITY_MAP, "codex") == "codex.shell"
    assert capability_id_for_tool("read_file", CODEX_TOOL_CAPABILITY_MAP, "codex") == "codex.read"
    assert capability_id_for_tool("str_replace_editor", CODEX_TOOL_CAPABILITY_MAP, "codex") == "codex.edit"


def test_capability_id_with_gemini_map() -> None:
    assert capability_id_for_tool("run_shell_command", GEMINI_TOOL_CAPABILITY_MAP, "gemini") == "gemini.run_shell_command"
    assert capability_id_for_tool("read_file", GEMINI_TOOL_CAPABILITY_MAP, "gemini") == "gemini.read_file"
    assert capability_id_for_tool("replace_in_file", GEMINI_TOOL_CAPABILITY_MAP, "gemini") == "gemini.edit"
    assert capability_id_for_tool("remove_files_and_dirs", GEMINI_TOOL_CAPABILITY_MAP, "gemini") == "gemini.delete"


def test_capability_id_unknown_tool_uses_prefix() -> None:
    result = capability_id_for_tool("unknown_tool_xyz", CODEX_TOOL_CAPABILITY_MAP, "codex")
    assert result == "codex.tool.unknown_tool_xyz"


def test_capability_id_mcp_pattern_uses_prefix() -> None:
    result = capability_id_for_tool("mcp__memory__store", None, "codex")
    assert result == "codex.mcp.memory.store"


# ---------------------------------------------------------------------------
# process_post_tool_use with Codex / Gemini maps
# ---------------------------------------------------------------------------

def _post_payload(session_id: str, tool_name: str) -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": {"command": "echo hi"},
        "tool_response": {"output": "hi", "exit_code": 0},
        "cwd": "/tmp",
    }


def test_codex_post_tool_uses_codex_capability_id(tmp_path) -> None:
    store_path = str(tmp_path / "codex.sqlite")
    process_post_tool_use(
        _post_payload("codex-session", "shell"),
        store_path,
        tool_map=CODEX_TOOL_CAPABILITY_MAP,
        agent_prefix="codex",
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("codex-session")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "codex.shell"


def test_gemini_post_tool_uses_gemini_capability_id(tmp_path) -> None:
    store_path = str(tmp_path / "gemini.sqlite")
    process_post_tool_use(
        _post_payload("gemini-session", "run_shell_command"),
        store_path,
        tool_map=GEMINI_TOOL_CAPABILITY_MAP,
        agent_prefix="gemini",
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("gemini-session")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "gemini.run_shell_command"


def test_codex_stop_uses_codex_session_capability(tmp_path) -> None:
    store_path = str(tmp_path / "codex-stop.sqlite")
    process_stop(
        {"session_id": "codex-stop-session", "transcript_path": ""},
        store_path,
        agent_prefix="codex",
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("codex-stop-session")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "codex.session"
    assert events[0]["event_type"] == "session_completed"


def test_gemini_stop_uses_gemini_session_capability(tmp_path) -> None:
    store_path = str(tmp_path / "gemini-stop.sqlite")
    process_stop(
        {"session_id": "gemini-stop-session", "transcript_path": ""},
        store_path,
        agent_prefix="gemini",
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("gemini-stop-session")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "gemini.session"


# ---------------------------------------------------------------------------
# Adapter capability descriptors
# ---------------------------------------------------------------------------

def test_codex_adapter_has_shell_capability() -> None:
    from chp_core.adapters.codex import CodexAdapter
    caps = {c.descriptor.id for c in CodexAdapter().capabilities()}
    assert "codex.shell" in caps
    assert "codex.read" in caps
    assert "codex.edit" in caps
    assert "codex.delete" in caps
    assert "codex.session" in caps


def test_codex_adapter_delete_is_high_risk() -> None:
    from chp_core.adapters.codex import CodexAdapter
    delete_cap = next(c for c in CodexAdapter().capabilities() if c.descriptor.id == "codex.delete")
    assert delete_cap.descriptor.risk == "high"


def test_gemini_adapter_has_core_capabilities() -> None:
    from chp_core.adapters.gemini_cli import GeminiCLIAdapter
    caps = {c.descriptor.id for c in GeminiCLIAdapter().capabilities()}
    assert "gemini.run_shell_command" in caps
    assert "gemini.read_file" in caps
    assert "gemini.write_file" in caps
    assert "gemini.edit" in caps
    assert "gemini.delete" in caps
    assert "gemini.web_search" in caps
    assert "gemini.session" in caps


def test_gemini_adapter_delete_is_high_risk() -> None:
    from chp_core.adapters.gemini_cli import GeminiCLIAdapter
    delete_cap = next(c for c in GeminiCLIAdapter().capabilities() if c.descriptor.id == "gemini.delete")
    assert delete_cap.descriptor.risk == "high"


def test_gemini_adapter_session_emits_session_completed() -> None:
    from chp_core.adapters.gemini_cli import GeminiCLIAdapter
    session_cap = next(c for c in GeminiCLIAdapter().capabilities() if c.descriptor.id == "gemini.session")
    assert "session_completed" in session_cap.descriptor.emits


# ---------------------------------------------------------------------------
# CLI subprocess tests
# ---------------------------------------------------------------------------

def _run_hook(cmd: str, payload: dict, store_path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "chp_core.cli", "hook", cmd, "--store", store_path],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _PACKAGES_DIR},
    )


def test_codex_post_tool_cli_exits_0(tmp_path) -> None:
    result = _run_hook("codex-post-tool", _post_payload("s1", "shell"), str(tmp_path / "s.sqlite"))
    assert result.returncode == 0


def test_codex_stop_cli_exits_0(tmp_path) -> None:
    result = _run_hook("codex-stop", {"session_id": "s2", "transcript_path": ""}, str(tmp_path / "s.sqlite"))
    assert result.returncode == 0


def test_gemini_post_tool_cli_exits_0(tmp_path) -> None:
    result = _run_hook("gemini-post-tool", _post_payload("s3", "run_shell_command"), str(tmp_path / "s.sqlite"))
    assert result.returncode == 0


def test_gemini_stop_cli_exits_0(tmp_path) -> None:
    result = _run_hook("gemini-stop", {"session_id": "s4", "transcript_path": ""}, str(tmp_path / "s.sqlite"))
    assert result.returncode == 0


def test_codex_evidence_has_correct_capability_id_via_cli(tmp_path) -> None:
    store_path = str(tmp_path / "verify.sqlite")
    _run_hook("codex-post-tool", _post_payload("codex-cli-test", "read_file"), store_path)
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("codex-cli-test")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "codex.read"


def test_gemini_evidence_has_correct_capability_id_via_cli(tmp_path) -> None:
    store_path = str(tmp_path / "verify2.sqlite")
    _run_hook("gemini-post-tool", _post_payload("gemini-cli-test", "write_file"), store_path)
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("gemini-cli-test")
    store.close()
    assert len(events) == 1
    assert events[0]["capability_id"] == "gemini.write_file"
