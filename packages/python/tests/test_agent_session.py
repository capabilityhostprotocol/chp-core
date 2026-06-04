"""Tests for v0.2.5 programmatic wrapping: AgentSession and wrap_tool_call."""

from __future__ import annotations

import pytest

from chp_core.hooks import CODEX_TOOL_CAPABILITY_MAP
from chp_core.policy import BlockPattern, PolicyConfig
from chp_core.session import AgentSession, wrap_tool_call
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# AgentSession
# ---------------------------------------------------------------------------

def test_agent_session_emits_session_completed_on_exit(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-exit-session"
    with AgentSession(store_path=store_path, session_id=session_id):
        pass
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    types = [e["event_type"] for e in events]
    assert "session_completed" in types


def test_agent_session_record_tool_emits_tool_use(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-record-session"
    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "echo hi"}, {"output": "hi", "exit_code": 0})
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    assert len(tool_events) == 1
    assert tool_events[0]["capability_id"] == "claude_code.bash"


def test_agent_session_record_failure_outcome(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-failure-session"
    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "bad"}, {"error": "not found", "exit_code": 1})
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    assert tool_events[0]["outcome"] == "failure"


def test_agent_session_wrap_calls_fn_and_records(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-wrap-session"
    calls: list[dict] = []

    def my_tool(inp: dict) -> dict:
        calls.append(inp)
        return {"output": "done"}

    with AgentSession(store_path=store_path, session_id=session_id) as session:
        result = session.wrap("Read", {"file_path": "/tmp/f.txt"}, my_tool)

    assert result == {"output": "done"}
    assert len(calls) == 1
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    assert any(e["event_type"] == "tool_use" for e in events)


def test_agent_session_wrap_records_failure_on_exception(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-wrap-exc-session"

    def bad_tool(inp: dict) -> dict:
        raise ValueError("tool exploded")

    with AgentSession(store_path=store_path, session_id=session_id) as session:
        with pytest.raises(ValueError, match="tool exploded"):
            session.wrap("Bash", {"command": "fail"}, bad_tool)

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    assert len(tool_events) == 1
    assert tool_events[0]["outcome"] == "failure"


def test_agent_session_preserves_session_id(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session = AgentSession(store_path=store_path, session_id="my-fixed-id")
    assert session.session_id == "my-fixed-id"


def test_agent_session_uses_custom_tool_map(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-codex-session"
    with AgentSession(
        store_path=store_path,
        session_id=session_id,
        agent_prefix="codex",
        tool_map=CODEX_TOOL_CAPABILITY_MAP,
    ) as session:
        session.record_tool("shell", {"command": "ls"}, {"output": ".", "exit_code": 0})
    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    assert tool_events[0]["capability_id"] == "codex.shell"


# ---------------------------------------------------------------------------
# wrap_tool_call
# ---------------------------------------------------------------------------

def test_wrap_tool_call_one_shot_emits_pre_and_post(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-wt-session"

    wrap_tool_call(
        "Read",
        {"file_path": "/tmp/f.txt"},
        fn=lambda inp: {"content": "hello"},
        store_path=store_path,
        session_id=session_id,
    )

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    types = [e["event_type"] for e in events]
    assert "tool_use_requested" in types
    assert "tool_use" in types


def test_wrap_tool_call_raises_on_policy_block(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])

    with pytest.raises(RuntimeError, match="CHP policy blocked"):
        wrap_tool_call(
            "Bash",
            {"command": "rm -rf /"},
            fn=lambda inp: {},
            store_path=store_path,
            policy=policy,
        )


def test_wrap_tool_call_records_fn_exception(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "test-wt-exc"

    with pytest.raises(RuntimeError, match="boom"):
        wrap_tool_call(
            "Bash",
            {"command": "fail"},
            fn=lambda inp: (_ for _ in ()).throw(RuntimeError("boom")),
            store_path=store_path,
            session_id=session_id,
        )

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    tool_events = [e for e in events if e["event_type"] == "tool_use"]
    assert tool_events[0]["outcome"] == "failure"
