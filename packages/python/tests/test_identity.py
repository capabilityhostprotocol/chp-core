"""Tests for §13.1 Identity invariant — subject propagation to ExecutionEvidence."""

from __future__ import annotations

import pytest

from chp_core import (
    CapabilityDescriptor,
    CorrelationContext,
    ExecutionEvidence,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)


async def _simple_cap(ctx, payload):
    return {"ok": True}


def _make_host(store_path: str) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(store_path)
    host = LocalCapabilityHost("test-identity", store=store)
    host.register(
        CapabilityDescriptor(id="identity.echo", version="1.0.0", description="Echo"),
        _simple_cap,
    )
    return host


class TestSubjectDefault:
    @pytest.mark.asyncio
    async def test_default_subject_on_evidence(self, tmp_path):
        host = _make_host(str(tmp_path / "ev.sqlite"))
        await host.ainvoke("identity.echo", {}, correlation={"correlation_id": "id-001"})
        events = host.replay("id-001")
        host.store.close()

        # Default subject is set on all execution events
        exec_events = [e for e in events if "execution" in e["event_type"]]
        assert exec_events, "no execution events emitted"
        for ev in exec_events:
            assert "subject" in ev, f"subject missing from {ev['event_type']}"
            assert ev["subject"]["id"] == "local"
            assert ev["subject"]["type"] == "user"

    @pytest.mark.asyncio
    async def test_custom_subject_propagates_to_all_events(self, tmp_path):
        host = _make_host(str(tmp_path / "ev.sqlite"))
        custom_subject = {"id": "agent-007", "type": "agent"}
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": "id-002"},
            subject=custom_subject,
        )
        events = host.replay("id-002")
        host.store.close()

        exec_events = [e for e in events if "execution" in e["event_type"]]
        assert exec_events, "no execution events"
        for ev in exec_events:
            assert ev.get("subject") == custom_subject, (
                f"expected {custom_subject}, got {ev.get('subject')} on {ev['event_type']}"
            )

    @pytest.mark.asyncio
    async def test_subject_in_to_dict_when_set(self, tmp_path):
        host = _make_host(str(tmp_path / "ev.sqlite"))
        custom_subject = {"id": "svc-x", "type": "service"}
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": "id-003"},
            subject=custom_subject,
        )
        events = host.replay("id-003")
        host.store.close()

        for ev in events:
            if "subject" in ev:
                assert ev["subject"] == custom_subject

    def test_subject_omitted_from_dict_when_none(self):
        ev = ExecutionEvidence(
            event_id="evt_x",
            event_type="execution_started",
            invocation_id="inv_x",
            capability_id="x",
            capability_version="1.0.0",
            host_id="h",
            correlation=CorrelationContext(correlation_id="corr_x"),
            subject=None,
        )
        d = ev.to_dict()
        assert "subject" not in d

    @pytest.mark.asyncio
    async def test_each_invocation_carries_its_own_subject(self, tmp_path):
        host = _make_host(str(tmp_path / "ev.sqlite"))
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": "id-a"},
            subject={"id": "agent-a", "type": "agent"},
        )
        await host.ainvoke(
            "identity.echo", {},
            correlation={"correlation_id": "id-b"},
            subject={"id": "agent-b", "type": "agent"},
        )
        events_a = host.replay("id-a")
        events_b = host.replay("id-b")
        host.store.close()

        subjects_a = {e["subject"]["id"] for e in events_a if e.get("subject")}
        subjects_b = {e["subject"]["id"] for e in events_b if e.get("subject")}
        assert subjects_a == {"agent-a"}
        assert subjects_b == {"agent-b"}
