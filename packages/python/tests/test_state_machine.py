"""Tests for StateMachineCapability — §6.3."""

from __future__ import annotations

import pytest

from chp_core.state_machine import InMemoryStateMachine, register_state_machine_capability
from chp_core.types import StateMachineDefinition


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_DEF = StateMachineDefinition(
    states=["queued", "running", "done", "failed"],
    transitions={
        "queued": ["running"],
        "running": ["done", "failed"],
    },
    initial_state="queued",
    terminal_states=["done", "failed"],
)


@pytest.fixture
def sm():
    return InMemoryStateMachine()


# ---------------------------------------------------------------------------
# Unit tests — InMemoryStateMachine
# ---------------------------------------------------------------------------

def test_create_sets_initial_state(sm):
    record = sm.create("job-1", SIMPLE_DEF, {})
    assert record.current_state == "queued"
    assert record.status == "queued"
    assert record.machine_id.startswith("sm_")


def test_create_rejects_bad_initial_state():
    bad = StateMachineDefinition(
        states=["a", "b"],
        transitions={"a": ["b"]},
        initial_state="c",  # not in states
        terminal_states=["b"],
    )
    sm = InMemoryStateMachine()
    with pytest.raises(ValueError, match="initial_state"):
        sm.create("x", bad, {})


def test_valid_transition_advances_state(sm):
    record = sm.create("job-2", SIMPLE_DEF, {})
    result = sm.transition(record.machine_id, "running")
    assert result.allowed is True
    assert result.from_state == "queued"
    assert result.to_state == "running"
    updated = sm.get(record.machine_id)
    assert updated.current_state == "running"
    assert updated.status == "running"


def test_transition_to_terminal_sets_done_status(sm):
    record = sm.create("job-3", SIMPLE_DEF, {})
    sm.transition(record.machine_id, "running")
    result = sm.transition(record.machine_id, "done")
    assert result.allowed is True
    updated = sm.get(record.machine_id)
    assert updated.status == "done"


def test_invalid_transition_is_rejected(sm):
    record = sm.create("job-4", SIMPLE_DEF, {})
    result = sm.transition(record.machine_id, "done")  # queued -> done not allowed
    assert result.allowed is False
    assert "not defined" in result.reason
    # state unchanged
    assert sm.get(record.machine_id).current_state == "queued"


def test_transition_on_terminal_machine_rejected(sm):
    record = sm.create("job-5", SIMPLE_DEF, {})
    sm.transition(record.machine_id, "running")
    sm.transition(record.machine_id, "done")
    result = sm.transition(record.machine_id, "running")  # already done
    assert result.allowed is False
    assert "terminal" in result.reason


def test_history_is_appended(sm):
    record = sm.create("job-6", SIMPLE_DEF, {})
    sm.transition(record.machine_id, "running")
    sm.transition(record.machine_id, "done")
    updated = sm.get(record.machine_id)
    assert len(updated.history) == 2
    assert updated.history[0]["from"] == "queued"
    assert updated.history[1]["from"] == "running"


def test_list_all(sm):
    sm.create("a", SIMPLE_DEF, {})
    sm.create("b", SIMPLE_DEF, {})
    assert len(sm.list_machines()) == 2


def test_list_filtered_by_status(sm):
    r1 = sm.create("a", SIMPLE_DEF, {})
    sm.create("b", SIMPLE_DEF, {})
    sm.transition(r1.machine_id, "running")
    running = sm.list_machines(status="running")
    assert len(running) == 1
    assert running[0].machine_id == r1.machine_id


def test_get_nonexistent_returns_none(sm):
    assert sm.get("sm_doesnotexist") is None


# ---------------------------------------------------------------------------
# Integration — through host
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_state_machine_via_host():
    from chp_core.host import LocalCapabilityHost
    from chp_core.store import SQLiteEvidenceStore

    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        path = f.name
    try:
        store = SQLiteEvidenceStore(path)
        host = LocalCapabilityHost("test-sm-host", store=store)
        register_state_machine_capability(host)

        result = await host.ainvoke("state_machine.create", {
            "name": "deploy-pipeline",
            "definition": {
                "states": ["pending", "building", "deploying", "live", "rollback"],
                "transitions": {
                    "pending": ["building"],
                    "building": ["deploying", "rollback"],
                    "deploying": ["live", "rollback"],
                },
                "initial_state": "pending",
                "terminal_states": ["live", "rollback"],
            },
            "context": {"repo": "chp-core"},
        })
        assert result.success
        machine_id = result.data["machine_id"]
        assert result.data["current_state"] == "pending"

        tr = await host.ainvoke("state_machine.transition", {"machine_id": machine_id, "event": "building"})
        assert tr.success
        assert tr.data["allowed"] is True

        got = await host.ainvoke("state_machine.get", {"machine_id": machine_id})
        assert got.success
        assert got.data["current_state"] == "building"

        store.close()
    finally:
        os.unlink(path)
