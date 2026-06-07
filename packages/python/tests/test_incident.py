"""Tests for InMemoryIncidentManager and incident capability — §9.5."""

from __future__ import annotations

import os
import tempfile

import pytest

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.incident import InMemoryIncidentManager, register_incident_capability
from chp_core.types import IncidentTrigger


@pytest.fixture
def manager():
    return InMemoryIncidentManager()


def test_open_creates_incident_in_open_status(manager):
    inc = manager.open("DB down", "P1")
    assert inc.incident_id.startswith("inc_")
    assert inc.status == "open"
    assert inc.severity == "P1"
    assert inc.title == "DB down"
    assert inc.resolved_at is None
    assert len(inc.timeline) == 1


def test_escalate_transitions_from_open(manager):
    inc = manager.open("CPU spike", "P2")
    escalated = manager.escalate(inc.incident_id, note="paging on-call")
    assert escalated.status == "escalated"
    assert any(e["event"] == "escalated" for e in escalated.timeline)


def test_resolve_sets_resolved_at(manager):
    inc = manager.open("Memory leak", "P3")
    resolved = manager.resolve(inc.incident_id, note="restarted pod")
    assert resolved.status == "resolved"
    assert resolved.resolved_at is not None


def test_close_requires_resolved_first(manager):
    inc = manager.open("Alert", "P4")
    with pytest.raises(ValueError, match="cannot transition"):
        manager.close(inc.incident_id)


def test_full_lifecycle_open_escalate_resolve_close(manager):
    inc = manager.open("Full lifecycle", "P2")
    manager.escalate(inc.incident_id)
    manager.resolve(inc.incident_id)
    closed = manager.close(inc.incident_id)
    assert closed.status == "closed"
    statuses = [e["event"] for e in closed.timeline]
    assert statuses == ["opened", "escalated", "resolved", "closed"]


def test_list_all_incidents(manager):
    manager.open("A", "P1")
    manager.open("B", "P2")
    manager.open("C", "P3")
    assert len(manager.list_incidents()) == 3


def test_list_filtered_by_status(manager):
    inc_a = manager.open("A", "P1")
    manager.open("B", "P2")
    manager.escalate(inc_a.incident_id)
    escalated = manager.list_incidents(status="escalated")
    assert len(escalated) == 1
    assert escalated[0].incident_id == inc_a.incident_id


def test_apply_remediation_appends_to_timeline(manager):
    inc = manager.open("Slow query", "P3")
    action = manager.apply_remediation(
        inc.incident_id, "killed long-running query", action_type="manual"
    )
    assert action.action_id.startswith("rem_")
    timeline_events = [e["event"] for e in manager.get(inc.incident_id).timeline]
    assert "remediation_applied" in timeline_events


def test_scan_for_triggers_fires_when_threshold_met():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        path = f.name
    try:
        store = SQLiteEvidenceStore(path)
        manager = InMemoryIncidentManager()

        # Manually write some execution_failed events
        from chp_core.types import (
            CorrelationContext,
            ExecutionEvidence,
            AssuranceMetadata,
            new_id,
            utc_now,
        )
        for _ in range(3):
            ev = ExecutionEvidence(
                event_id=new_id("evt"),
                event_type="execution_failed",
                invocation_id=new_id("inv"),
                capability_id="test.cap",
                capability_version="1.0.0",
                host_id="test-host",
                correlation=CorrelationContext(correlation_id="scan-test"),
                timestamp=utc_now(),
                sequence=0,
                redacted=False,
            )
            store.append(ev)

        trigger = IncidentTrigger(pattern="execution_failed", threshold=3, window_seconds=3600)
        fired = manager.scan_for_triggers(store, [trigger])
        assert len(fired) == 1
        assert "execution_failed" in fired[0].title

        store.close()
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_incident_via_host():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        path = f.name
    try:
        store = SQLiteEvidenceStore(path)
        host = LocalCapabilityHost("test-incident", store=store)
        register_incident_capability(host)

        r_open = await host.ainvoke(
            "incident.open",
            {"title": "Test incident", "severity": "P3"},
        )
        assert r_open.success
        incident_id = r_open.data["incident_id"]
        assert r_open.data["status"] == "open"

        r_resolve = await host.ainvoke(
            "incident.resolve",
            {"incident_id": incident_id, "note": "fixed"},
        )
        assert r_resolve.success
        assert r_resolve.data["status"] == "resolved"

        store.close()
    finally:
        os.unlink(path)
