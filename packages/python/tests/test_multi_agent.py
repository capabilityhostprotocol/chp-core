"""Tests for v0.2.3 multi-agent correlation: session_spawn events and session tree."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from chp_core.hooks import process_post_tool_use, process_stop
from chp_core.store import SQLiteEvidenceStore


_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


def _post_payload(
    session_id: str = "parent-session",
    tool_name: str = "Bash",
    tool_input: dict | None = None,
    tool_response: dict | None = None,
) -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": tool_input or {"command": "echo hi"},
        "tool_response": tool_response or {"output": "hi", "exit_code": 0},
        "cwd": "/tmp",
    }


# ---------------------------------------------------------------------------
# session_spawn emission
# ---------------------------------------------------------------------------

def test_agent_spawn_emits_session_spawn_event(tmp_path) -> None:
    store_path = str(tmp_path / "spawn.sqlite")
    process_post_tool_use(
        _post_payload(
            tool_name="Agent",
            tool_input={"description": "summarise", "prompt": "summarise this"},
            tool_response={"session_id": "child-session-001", "result": "done"},
        ),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("parent-session")
    store.close()

    spawn_events = [e for e in events if e["event_type"] == "session_spawn"]
    assert len(spawn_events) == 1
    payload = spawn_events[0]["payload"]
    assert payload["child_session_id"] == "child-session-001"
    assert payload["parent_session_id"] == "parent-session"
    assert payload["tool_name"] == "Agent"


def test_task_spawn_also_emits_session_spawn(tmp_path) -> None:
    store_path = str(tmp_path / "task.sqlite")
    process_post_tool_use(
        _post_payload(
            tool_name="Task",
            tool_input={"description": "run task"},
            tool_response={"session_id": "task-child-001"},
        ),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("parent-session")
    store.close()
    spawn_events = [e for e in events if e["event_type"] == "session_spawn"]
    assert len(spawn_events) == 1
    assert spawn_events[0]["payload"]["child_session_id"] == "task-child-001"


def test_non_agent_tool_does_not_emit_session_spawn(tmp_path) -> None:
    store_path = str(tmp_path / "no-spawn.sqlite")
    process_post_tool_use(
        _post_payload(tool_name="Bash", tool_response={"output": "hi", "exit_code": 0}),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("parent-session")
    store.close()
    spawn_events = [e for e in events if e["event_type"] == "session_spawn"]
    assert len(spawn_events) == 0


def test_agent_without_session_id_in_response_does_not_emit_spawn(tmp_path) -> None:
    store_path = str(tmp_path / "no-id.sqlite")
    process_post_tool_use(
        _post_payload(
            tool_name="Agent",
            tool_response={"result": "done"},  # no session_id key
        ),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("parent-session")
    store.close()
    spawn_events = [e for e in events if e["event_type"] == "session_spawn"]
    assert len(spawn_events) == 0


def test_session_spawn_event_capability_id(tmp_path) -> None:
    store_path = str(tmp_path / "cap.sqlite")
    process_post_tool_use(
        _post_payload(
            tool_name="Agent",
            tool_response={"session_id": "child-cap-001"},
        ),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("parent-session")
    store.close()
    spawn = next(e for e in events if e["event_type"] == "session_spawn")
    assert spawn["capability_id"] == "claude_code.session_spawn"


# ---------------------------------------------------------------------------
# store.children_of
# ---------------------------------------------------------------------------

def test_children_of_returns_empty_for_no_spawns(tmp_path) -> None:
    store_path = str(tmp_path / "empty.sqlite")
    process_post_tool_use(_post_payload(), store_path)
    store = SQLiteEvidenceStore(store_path)
    children = store.children_of("parent-session")
    store.close()
    assert children == []


def test_children_of_returns_child_session_ids(tmp_path) -> None:
    store_path = str(tmp_path / "children.sqlite")
    for child_id in ("child-001", "child-002"):
        process_post_tool_use(
            _post_payload(
                tool_name="Agent",
                tool_response={"session_id": child_id},
            ),
            store_path,
        )
    store = SQLiteEvidenceStore(store_path)
    children = store.children_of("parent-session")
    store.close()
    assert set(children) == {"child-001", "child-002"}


def test_children_of_does_not_cross_sessions(tmp_path) -> None:
    store_path = str(tmp_path / "cross.sqlite")
    process_post_tool_use(
        _post_payload(
            session_id="session-A",
            tool_name="Agent",
            tool_response={"session_id": "child-of-A"},
        ),
        store_path,
    )
    process_post_tool_use(
        _post_payload(
            session_id="session-B",
            tool_name="Agent",
            tool_response={"session_id": "child-of-B"},
        ),
        store_path,
    )
    store = SQLiteEvidenceStore(store_path)
    assert store.children_of("session-A") == ["child-of-A"]
    assert store.children_of("session-B") == ["child-of-B"]
    store.close()


# ---------------------------------------------------------------------------
# chp session tree CLI
# ---------------------------------------------------------------------------

def _run_session_tree(session_id: str, store_path: str, depth: int | None = None) -> subprocess.CompletedProcess:
    args = [sys.executable, "-m", "chp_core.cli", "session", "tree", session_id, "--store", store_path]
    if depth is not None:
        args += ["--depth", str(depth)]
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _PACKAGES_DIR},
    )


def test_session_tree_cli_single_session(tmp_path) -> None:
    store_path = str(tmp_path / "tree.sqlite")
    process_post_tool_use(_post_payload(), store_path)
    result = _run_session_tree("parent-session", store_path)
    assert result.returncode == 0
    tree = json.loads(result.stdout)
    assert tree["session_id"] == "parent-session"
    assert tree["child_count"] == 0
    assert tree["children"] == []


def test_session_tree_cli_with_child(tmp_path) -> None:
    store_path = str(tmp_path / "tree2.sqlite")
    process_post_tool_use(
        _post_payload(
            tool_name="Agent",
            tool_response={"session_id": "child-tree-001"},
        ),
        store_path,
    )
    process_post_tool_use(
        _post_payload(session_id="child-tree-001"),
        store_path,
    )
    result = _run_session_tree("parent-session", store_path)
    assert result.returncode == 0
    tree = json.loads(result.stdout)
    assert tree["child_count"] == 1
    assert len(tree["children"]) == 1
    child = tree["children"][0]
    assert child["session_id"] == "child-tree-001"
    assert child["tool_count"] == 1


def test_session_tree_cli_depth_limit(tmp_path) -> None:
    store_path = str(tmp_path / "depth.sqlite")
    # A → B → C (three levels deep)
    for parent, child in (("root", "level-1"), ("level-1", "level-2")):
        process_post_tool_use(
            _post_payload(
                session_id=parent,
                tool_name="Agent",
                tool_response={"session_id": child},
            ),
            store_path,
        )
        process_post_tool_use(_post_payload(session_id=child), store_path)

    result = _run_session_tree("root", store_path, depth=1)
    assert result.returncode == 0
    tree = json.loads(result.stdout)
    level1 = tree["children"][0]
    assert level1.get("truncated") is True or level1.get("child_count") == 0 or level1["children"] == []


def test_session_tree_unknown_session_returns_empty_tree(tmp_path) -> None:
    store_path = str(tmp_path / "empty-tree.sqlite")
    # Create the store file without adding any events
    SQLiteEvidenceStore(store_path).close()
    result = _run_session_tree("nonexistent-session", store_path)
    assert result.returncode == 0
    tree = json.loads(result.stdout)
    assert tree["session_id"] == "nonexistent-session"
    assert tree["tool_count"] == 0
    assert tree["children"] == []
