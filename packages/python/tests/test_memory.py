"""Tests for MemoryCapability, register_memory_capability, and AgentSessionDescriptor."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from chp_core import (
    AgentSessionDescriptor,
    AutonomyTier,
    COGNITION_EVIDENCE_TYPES,
    LocalCapabilityHost,
    MemoryCapability,
    MemoryScope,
    SESSION_EVIDENCE_TYPES,
    SQLiteEvidenceStore,
    register_memory_capability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_mem(tmp_path: Path) -> MemoryCapability:
    mem = MemoryCapability(tmp_path / "memory.sqlite")
    yield mem
    mem.close()


@pytest.fixture
def tmp_mem_and_host(tmp_path: Path):
    store = SQLiteEvidenceStore(str(tmp_path / "evidence.sqlite"))
    host = LocalCapabilityHost("test-host", store=store)
    mem = MemoryCapability(str(tmp_path / "memory.sqlite"))
    register_memory_capability(host, mem)
    yield host, mem, store
    mem.close()


# ── MemoryCapability: basic CRUD ──────────────────────────────────────────────


def test_set_and_get_roundtrip(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("key1", "hello")
    assert tmp_mem.get("key1") == "hello"


def test_get_missing_key_returns_none(tmp_mem: MemoryCapability) -> None:
    assert tmp_mem.get("nonexistent") is None


def test_delete_existing_returns_true(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("x", 1)
    assert tmp_mem.delete("x") is True


def test_delete_existing_removes_key(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("x", 1)
    tmp_mem.delete("x")
    assert tmp_mem.get("x") is None


def test_delete_missing_returns_false(tmp_mem: MemoryCapability) -> None:
    assert tmp_mem.delete("nonexistent") is False


def test_list_empty_scope_returns_empty(tmp_mem: MemoryCapability) -> None:
    assert tmp_mem.list() == []


def test_list_returns_all_keys_sorted(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("z_key", 1)
    tmp_mem.set("a_key", 2)
    tmp_mem.set("m_key", 3)
    assert tmp_mem.list() == ["a_key", "m_key", "z_key"]


def test_overwrite_updates_value(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("v", "first")
    tmp_mem.set("v", "second")
    assert tmp_mem.get("v") == "second"


# ── MemoryCapability: scope isolation ─────────────────────────────────────────


def test_scope_isolation_session_vs_project(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("shared_key", "session_val", scope="session", scope_id="s1")
    tmp_mem.set("shared_key", "project_val", scope="project", scope_id="proj-a")
    assert tmp_mem.get("shared_key", scope="session", scope_id="s1") == "session_val"
    assert tmp_mem.get("shared_key", scope="project", scope_id="proj-a") == "project_val"


def test_scope_id_isolation(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("k", "v1", scope="session", scope_id="s1")
    tmp_mem.set("k", "v2", scope="session", scope_id="s2")
    assert tmp_mem.get("k", scope="session", scope_id="s1") == "v1"
    assert tmp_mem.get("k", scope="session", scope_id="s2") == "v2"


def test_list_scope_isolation(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("a", 1, scope="project", scope_id="p1")
    tmp_mem.set("b", 2, scope="project", scope_id="p2")
    assert tmp_mem.list(scope="project", scope_id="p1") == ["a"]
    assert tmp_mem.list(scope="project", scope_id="p2") == ["b"]


def test_delete_scope_isolation(tmp_mem: MemoryCapability) -> None:
    tmp_mem.set("k", "v", scope="session", scope_id="s1")
    tmp_mem.set("k", "v", scope="session", scope_id="s2")
    tmp_mem.delete("k", scope="session", scope_id="s1")
    assert tmp_mem.get("k", scope="session", scope_id="s1") is None
    assert tmp_mem.get("k", scope="session", scope_id="s2") == "v"


# ── MemoryCapability: value types ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        42,
        3.14,
        True,
        False,
        None,
        "a string",
        [1, 2, 3],
        {"nested": {"deep": [True, None]}},
        [],
        {},
    ],
)
def test_json_types_roundtrip(tmp_mem: MemoryCapability, value: Any) -> None:
    tmp_mem.set("typed", value)
    assert tmp_mem.get("typed") == value


# ── MemoryCapability: persistence ─────────────────────────────────────────────


def test_data_persists_after_close_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "memory.sqlite"
    mem1 = MemoryCapability(path)
    mem1.set("persist_key", "persist_value")
    mem1.close()

    mem2 = MemoryCapability(path)
    assert mem2.get("persist_key") == "persist_value"
    mem2.close()


def test_close_is_idempotent(tmp_mem: MemoryCapability) -> None:
    tmp_mem.close()
    tmp_mem.close()  # should not raise


# ── register_memory_capability: host integration ──────────────────────────────


def test_register_exposes_four_capabilities(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    descriptor = host.descriptor()
    ids = {cap["id"] for cap in descriptor.to_dict()["capabilities"]}
    assert {"memory.get", "memory.set", "memory.delete", "memory.list"}.issubset(ids)


def test_memory_set_via_host_invocation(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    result = asyncio.run(
        host.ainvoke("memory.set", {"key": "x", "value": 99, "scope": "session", "scope_id": "s1"})
    )
    assert result.success
    assert mem.get("x", scope="session", scope_id="s1") == 99


def test_memory_get_via_host_invocation(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    mem.set("y", "hello", scope="project", scope_id="p1")
    result = asyncio.run(
        host.ainvoke("memory.get", {"key": "y", "scope": "project", "scope_id": "p1"})
    )
    assert result.success
    assert result.data["value"] == "hello"
    assert result.data["found"] is True


def test_memory_get_missing_via_host_returns_not_found(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    result = asyncio.run(host.ainvoke("memory.get", {"key": "nope"}))
    assert result.success
    assert result.data["found"] is False
    assert result.data["value"] is None


def test_memory_delete_via_host(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    mem.set("del_me", "val")
    result = asyncio.run(host.ainvoke("memory.delete", {"key": "del_me"}))
    assert result.success
    assert result.data["existed"] is True
    assert mem.get("del_me") is None


def test_memory_list_via_host(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    mem.set("a", 1)
    mem.set("b", 2)
    result = asyncio.run(host.ainvoke("memory.list", {}))
    assert result.success
    assert set(result.data["keys"]) == {"a", "b"}
    assert result.data["count"] == 2


def test_memory_set_emits_evidence_events(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    result = asyncio.run(host.ainvoke("memory.set", {"key": "ev_test", "value": "data"}))
    assert result.success
    events = store.by_correlation(result.correlation.correlation_id)
    event_types = {e["event_type"] for e in events}
    assert "execution_started" in event_types
    assert "memory_written" in event_types
    assert "execution_completed" in event_types


def test_memory_get_emits_memory_read_event(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    mem.set("ev_key", "ev_val")
    result = asyncio.run(host.ainvoke("memory.get", {"key": "ev_key"}))
    events = store.by_correlation(result.correlation.correlation_id)
    event_types = [e["event_type"] for e in events]
    assert "memory_read" in event_types


def test_memory_delete_emits_memory_deleted_event(tmp_mem_and_host) -> None:
    host, mem, store = tmp_mem_and_host
    mem.set("del_ev", "v")
    result = asyncio.run(host.ainvoke("memory.delete", {"key": "del_ev"}))
    events = store.by_correlation(result.correlation.correlation_id)
    event_types = [e["event_type"] for e in events]
    assert "memory_deleted" in event_types


# ── AgentSessionDescriptor ────────────────────────────────────────────────────


def test_descriptor_defaults() -> None:
    d = AgentSessionDescriptor(session_id="s1", intent="test")
    assert d.memory_scope == "session"
    assert d.autonomy_tier == "supervised"
    assert d.tool_manifest == []
    assert d.parent_session_id is None
    assert d.model is None


def test_descriptor_roundtrip_via_to_dict_and_from_mapping() -> None:
    d = AgentSessionDescriptor(
        session_id="s1",
        intent="do something",
        model="claude-sonnet-4-6",
        memory_scope="project",
        autonomy_tier="approval_required",
        tool_manifest=["bash", "read"],
        parent_session_id="parent-001",
        metadata={"key": "value"},
    )
    restored = AgentSessionDescriptor.from_mapping(d.to_dict())
    assert restored.session_id == d.session_id
    assert restored.intent == d.intent
    assert restored.model == d.model
    assert restored.memory_scope == d.memory_scope
    assert restored.autonomy_tier == d.autonomy_tier
    assert restored.tool_manifest == d.tool_manifest
    assert restored.parent_session_id == d.parent_session_id
    assert restored.metadata == d.metadata


def test_descriptor_from_mapping_minimal() -> None:
    d = AgentSessionDescriptor.from_mapping({"session_id": "s2", "intent": "minimal"})
    assert d.session_id == "s2"
    assert d.intent == "minimal"
    assert d.memory_scope == "session"
    assert d.autonomy_tier == "supervised"


# ── AgentSession with descriptor emits agent_session_started ──────────────────


def test_agent_session_emits_started_event_with_descriptor(tmp_path: Path) -> None:
    from chp_core import AgentSession

    store_path = str(tmp_path / "evidence.sqlite")
    descriptor = AgentSessionDescriptor(
        session_id="sess-descriptor-test",
        intent="run memory tests",
        model="claude-sonnet-4-6",
    )
    with AgentSession(store_path=store_path, descriptor=descriptor):
        pass

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("sess-descriptor-test")
    event_types = [e["event_type"] for e in events]
    assert "agent_session_started" in event_types
    store.close()


def test_agent_session_no_descriptor_no_started_event(tmp_path: Path) -> None:
    from chp_core import AgentSession

    store_path = str(tmp_path / "evidence.sqlite")
    with AgentSession(store_path=store_path, session_id="sess-no-descriptor"):
        pass

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("sess-no-descriptor")
    event_types = [e["event_type"] for e in events]
    assert "agent_session_started" not in event_types
    store.close()


def test_agent_session_descriptor_sets_session_id(tmp_path: Path) -> None:
    from chp_core import AgentSession

    descriptor = AgentSessionDescriptor(session_id="specific-id", intent="test")
    session = AgentSession(descriptor=descriptor)
    assert session.session_id == "specific-id"


# ── Type constants ─────────────────────────────────────────────────────────────


def test_cognition_evidence_types_contains_memory_events() -> None:
    assert "memory_read" in COGNITION_EVIDENCE_TYPES
    assert "memory_written" in COGNITION_EVIDENCE_TYPES
    assert "memory_deleted" in COGNITION_EVIDENCE_TYPES


def test_session_evidence_types_contains_session_events() -> None:
    assert "agent_session_started" in SESSION_EVIDENCE_TYPES
    assert "agent_session_resumed" in SESSION_EVIDENCE_TYPES
    assert "agent_session_completed" in SESSION_EVIDENCE_TYPES
