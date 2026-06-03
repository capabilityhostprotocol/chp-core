"""Tests for v0.2.2 pre-tool governance: policy engine and hook integration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from chp_core.hooks import process_pre_tool_use
from chp_core.policy import (
    BlockPattern,
    PolicyConfig,
    PreToolResult,
    evaluate_policy,
    load_policy,
)
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Policy evaluation unit tests
# ---------------------------------------------------------------------------

def test_no_policy_always_passes() -> None:
    result = evaluate_policy(
        "claude_code.bash",
        {"command": "rm -rf /"},
        PolicyConfig(),
    )
    assert not result.should_block
    assert result.capability_id == "claude_code.bash"


def test_block_by_capability_id() -> None:
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
    result = evaluate_policy("claude_code.bash", {"command": "echo hi"}, policy)
    assert result.should_block
    assert "claude_code.bash" in (result.reason or "")


def test_block_capability_id_no_match() -> None:
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
    result = evaluate_policy("claude_code.read", {"file_path": "/etc/passwd"}, policy)
    assert not result.should_block


def test_block_by_pattern_match() -> None:
    policy = PolicyConfig(
        block_patterns=[
            BlockPattern(
                capability_id="claude_code.bash",
                field="command",
                pattern=r"rm -rf /",
                reason="unscoped deletion",
            )
        ],
    )
    result = evaluate_policy("claude_code.bash", {"command": "rm -rf /"}, policy)
    assert result.should_block
    assert result.reason == "unscoped deletion"


def test_block_pattern_no_match() -> None:
    policy = PolicyConfig(
        block_patterns=[
            BlockPattern(
                capability_id="claude_code.bash",
                field="command",
                pattern=r"rm -rf /",
                reason="unscoped deletion",
            )
        ],
    )
    result = evaluate_policy("claude_code.bash", {"command": "echo hello"}, policy)
    assert not result.should_block


def test_block_pattern_wrong_capability() -> None:
    policy = PolicyConfig(
        block_patterns=[
            BlockPattern(
                capability_id="claude_code.bash",
                field="command",
                pattern="secret",
                reason="blocked",
            )
        ],
    )
    result = evaluate_policy("claude_code.read", {"file_path": "secret.txt"}, policy)
    assert not result.should_block


def test_block_pattern_invalid_regex_falls_back_to_substring() -> None:
    policy = PolicyConfig(
        block_patterns=[
            BlockPattern(
                capability_id="claude_code.bash",
                field="command",
                pattern="[invalid regex",
                reason="blocked",
            )
        ],
    )
    result = evaluate_policy("claude_code.bash", {"command": "[invalid regex is here"}, policy)
    assert result.should_block


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------

def test_load_policy_from_file(tmp_path: "pytest.TempPathFactory") -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "version": "1",
        "block_capability_ids": ["claude_code.bash"],
        "block_patterns": [
            {
                "capability_id": "claude_code.bash",
                "field": "command",
                "pattern": "rm",
                "reason": "no deletion",
            }
        ],
    }))
    config = load_policy(str(policy_file))
    assert config is not None
    assert "claude_code.bash" in config.block_capability_ids
    assert len(config.block_patterns) == 1
    assert config.block_patterns[0].reason == "no deletion"


def test_load_policy_returns_none_when_missing() -> None:
    config = load_policy("/nonexistent/path/policy.json")
    assert config is None


# ---------------------------------------------------------------------------
# process_pre_tool_use integration
# ---------------------------------------------------------------------------

def _make_payload(tool: str = "Bash", command: str = "echo hi") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "test-pretool-session",
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": "/tmp",
    }


def test_process_pre_tool_emits_tool_use_requested(tmp_path) -> None:
    store_path = str(tmp_path / "test.sqlite")
    process_pre_tool_use(_make_payload(), store_path, policy=None)
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("test-pretool-session")
    store.close()
    assert len(events) == 1
    assert events[0]["event_type"] == "tool_use_requested"


def test_process_pre_tool_emits_success_outcome_when_passed(tmp_path) -> None:
    store_path = str(tmp_path / "test.sqlite")
    process_pre_tool_use(_make_payload(), store_path, policy=None)
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("test-pretool-session")
    store.close()
    assert events[0]["outcome"] == "success"


def test_process_pre_tool_emits_denied_outcome_when_blocked(tmp_path) -> None:
    store_path = str(tmp_path / "test.sqlite")
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
    process_pre_tool_use(_make_payload(), store_path, policy=policy)
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("test-pretool-session")
    store.close()
    assert events[0]["outcome"] == "denied"


def test_process_pre_tool_returns_block_result(tmp_path) -> None:
    store_path = str(tmp_path / "test.sqlite")
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
    result = process_pre_tool_use(_make_payload(), store_path, policy=policy)
    assert isinstance(result, PreToolResult)
    assert result.should_block is True


def test_process_pre_tool_returns_pass_result(tmp_path) -> None:
    store_path = str(tmp_path / "test.sqlite")
    result = process_pre_tool_use(_make_payload(), store_path, policy=None)
    assert result.should_block is False


# ---------------------------------------------------------------------------
# CLI subprocess tests
# ---------------------------------------------------------------------------

_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


def _run_hook_pre_tool(payload: dict, extra_args: list[str] | None = None, policy_data: dict | None = None) -> subprocess.CompletedProcess:
    args = [sys.executable, "-m", "chp_core.cli", "hook", "pre-tool"]
    if extra_args:
        args.extend(extra_args)
    env = {**os.environ, "PYTHONPATH": _PACKAGES_DIR}
    with tempfile.TemporaryDirectory() as tmpdir:
        store = os.path.join(tmpdir, "test.sqlite")
        args += ["--store", store]
        if policy_data is not None:
            policy_path = os.path.join(tmpdir, "policy.json")
            with open(policy_path, "w") as f:
                json.dump(policy_data, f)
            args += ["--policy", policy_path]
        return subprocess.run(
            args,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )


def test_hook_pre_tool_cli_exits_0_when_passed() -> None:
    result = _run_hook_pre_tool({"session_id": "s1", "tool_name": "Read", "tool_input": {}, "cwd": "/tmp"})
    assert result.returncode == 0


def test_hook_pre_tool_cli_exits_2_when_blocked() -> None:
    payload = {"session_id": "s2", "tool_name": "Bash", "tool_input": {"command": "echo hi"}, "cwd": "/tmp"}
    policy = {"version": "1", "block_capability_ids": ["claude_code.bash"], "block_patterns": []}
    result = _run_hook_pre_tool(payload, policy_data=policy)
    assert result.returncode == 2
    assert "blocked" in result.stderr.lower()


def test_hook_pre_tool_cli_exits_0_on_bad_json() -> None:
    args = [sys.executable, "-m", "chp_core.cli", "hook", "pre-tool"]
    env = {**os.environ, "PYTHONPATH": _PACKAGES_DIR}
    with tempfile.TemporaryDirectory() as tmpdir:
        args += ["--store", os.path.join(tmpdir, "s.sqlite")]
        result = subprocess.run(args, input="not json", capture_output=True, text=True, env=env)
    assert result.returncode == 0
