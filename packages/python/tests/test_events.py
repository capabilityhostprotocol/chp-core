"""Tests for EventBusCapability — v0.4.4."""

from __future__ import annotations

import json
import pytest

from chp_core import (
    DomainEventQueryResult,
    DomainEventRecord,
    EventBusCapability,
    InMemoryEventBus,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    register_event_bus_capability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def bus():
    return InMemoryEventBus()


@pytest.fixture
def tmp_host_and_bus(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-events", store=store)
    bus = InMemoryEventBus()
    register_event_bus_capability(host, bus)
    yield host, bus, store
    store.close()


# ── TestInMemoryEventBus ───────────────────────────────────────────────────────


class TestInMemoryEventBus:
    def test_emit_returns_domain_event_record(self, bus):
        r = bus.emit_event("order.placed", "orders", {"id": "o1"})
        assert isinstance(r, DomainEventRecord)
        assert r.event_type == "order.placed"
        assert r.source == "orders"

    def test_emit_data_hash_is_sha256(self, bus):
        r = bus.emit_event("x", "s", {"key": "value"})
        assert r.data_hash.startswith("sha256:")
        assert len(r.data_hash) == 7 + 64  # "sha256:" + 64 hex chars

    def test_emit_event_id_auto_generated(self, bus):
        r = bus.emit_event("x", "s", {})
        assert r.event_id.startswith("devt_")

    def test_emit_preserves_full_data(self, bus):
        data = {"order_id": "123", "amount": 99.99}
        r = bus.emit_event("order.placed", "orders", data)
        assert r.data == data

    def test_query_all_returns_all_events(self, bus):
        bus.emit_event("a", "src", {})
        bus.emit_event("b", "src", {})
        bus.emit_event("c", "src", {})
        result = bus.query_events()
        assert isinstance(result, DomainEventQueryResult)
        assert result.event_count == 3

    def test_query_by_event_type_filters(self, bus):
        bus.emit_event("order.placed", "orders", {})
        bus.emit_event("order.shipped", "fulfillment", {})
        bus.emit_event("order.placed", "orders", {})
        result = bus.query_events(event_type="order.placed")
        assert result.event_count == 2
        assert all(e.event_type == "order.placed" for e in result.events)

    def test_query_by_source_filters(self, bus):
        bus.emit_event("x", "service-a", {})
        bus.emit_event("x", "service-b", {})
        result = bus.query_events(source="service-a")
        assert result.event_count == 1
        assert result.events[0].source == "service-a"

    def test_query_limit_respected(self, bus):
        for i in range(5):
            bus.emit_event("evt", "src", {"i": i})
        result = bus.query_events(limit=3)
        assert result.event_count == 3

    def test_query_empty_returns_empty_result(self, bus):
        result = bus.query_events()
        assert result.event_count == 0
        assert result.events == []

    def test_event_type_filter_preserved_in_result(self, bus):
        bus.emit_event("order.placed", "s", {})
        result = bus.query_events(event_type="order.placed")
        assert result.event_type_filter == "order.placed"

    def test_correlation_id_stored_on_record(self, bus):
        r = bus.emit_event("x", "s", {}, correlation_id="corr-999")
        assert r.correlation_id == "corr-999"


# ── TestEventBusDescriptor ────────────────────────────────────────────────────


class TestEventBusDescriptor:
    def _descriptors(self, host):
        return [entry.descriptor for entry in host._capabilities.values()]

    def test_registers_two_capabilities(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        event_caps = [d for d in self._descriptors(host) if d.id.startswith("events.")]
        assert len(event_caps) == 2

    def test_registers_emit_and_query(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        ids = {d.id for d in self._descriptors(host)}
        assert "events.emit" in ids
        assert "events.query" in ids

    def test_both_have_process_workflow_category(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        event_caps = [d for d in self._descriptors(host) if d.id.startswith("events.")]
        for cap in event_caps:
            category = cap.category.value if hasattr(cap.category, "value") else cap.category
            assert category == "process_workflow", f"{cap.id} has wrong category"

    def test_emit_cap_has_domain_event_emitted_in_emits(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        emit_cap = next(d for d in self._descriptors(host) if d.id == "events.emit")
        assert "domain_event_emitted" in emit_cap.emits

    def test_base_class_raises_not_implemented(self):
        base = EventBusCapability()
        with pytest.raises(NotImplementedError):
            base.emit_event("x", "s", {})
        with pytest.raises(NotImplementedError):
            base.query_events()


# ── TestEventBusEvidenceEmission ──────────────────────────────────────────────


class TestEventBusEvidenceEmission:
    @pytest.mark.asyncio
    async def test_domain_event_emitted_in_chain(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {}},
            correlation={"correlation_id": "ev-001"},
        )
        types = {e["event_type"] for e in host.replay("ev-001")}
        assert "domain_event_emitted" in types

    @pytest.mark.asyncio
    async def test_domain_event_emitted_payload_has_data_hash_not_data(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        await host.ainvoke(
            "events.emit",
            {"event_type": "order.placed", "source": "orders", "data": {"secret": "value"}},
            correlation={"correlation_id": "ev-002"},
        )
        events = host.replay("ev-002")
        emitted = next(e for e in events if e["event_type"] == "domain_event_emitted")
        payload = emitted.get("payload") or {}
        assert payload.get("data_hash", "").startswith("sha256:")
        assert "data" not in payload
        assert "secret" not in str(payload)

    @pytest.mark.asyncio
    async def test_domain_events_queried_in_chain(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        await host.ainvoke(
            "events.query",
            {"event_type": "order.placed"},
            correlation={"correlation_id": "ev-003"},
        )
        types = {e["event_type"] for e in host.replay("ev-003")}
        assert "domain_events_queried" in types

    @pytest.mark.asyncio
    async def test_domain_events_queried_payload_has_count_not_bodies(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        bus.emit_event("order.placed", "orders", {"id": "o1"})
        await host.ainvoke(
            "events.query", {}, correlation={"correlation_id": "ev-004"}
        )
        events = host.replay("ev-004")
        queried = next(e for e in events if e["event_type"] == "domain_events_queried")
        payload = queried.get("payload") or {}
        assert "event_count" in payload
        assert "events" not in payload

    @pytest.mark.asyncio
    async def test_domain_event_emitted_payload_has_event_id_and_type(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        await host.ainvoke(
            "events.emit",
            {"event_type": "order.shipped", "source": "fulfillment"},
            correlation={"correlation_id": "ev-005"},
        )
        events = host.replay("ev-005")
        emitted = next(e for e in events if e["event_type"] == "domain_event_emitted")
        payload = emitted.get("payload") or {}
        assert "event_id" in payload
        assert payload["event_type"] == "order.shipped"
        assert payload["source"] == "fulfillment"

    @pytest.mark.asyncio
    async def test_hash_chain_intact(self, tmp_host_and_bus):
        host, bus, store = tmp_host_and_bus
        await host.ainvoke(
            "events.emit",
            {"event_type": "x", "source": "s"},
            correlation={"correlation_id": "ev-006"},
        )
        records = store.by_correlation_with_hashes("ev-006")
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_execution_started_and_completed_present(self, tmp_host_and_bus):
        host, bus, _ = tmp_host_and_bus
        await host.ainvoke(
            "events.emit",
            {"event_type": "x", "source": "s"},
            correlation={"correlation_id": "ev-007"},
        )
        types = {e["event_type"] for e in host.replay("ev-007")}
        assert "execution_started" in types
        assert "execution_completed" in types


# ── TestEventsReportCLI ───────────────────────────────────────────────────────


class TestEventsReportCLI:
    @pytest.mark.asyncio
    async def test_returns_0_when_events_found(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_events_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-evt", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)
        await host.ainvoke("events.emit", {"event_type": "x", "source": "s"}, correlation={"correlation_id": "cli-ev-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-ev-1", store=store_path)
        rc = cmd_session_events_report(args)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_returns_1_for_no_domain_events(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_events_report
        from chp_core import InMemoryWorkflow, register_workflow_capability

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-nev", store=store)
        wf = InMemoryWorkflow()
        register_workflow_capability(host, wf)
        await host.ainvoke("workflow.run", {"steps": []}, correlation={"correlation_id": "cli-nev-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-nev-1", store=store_path)
        rc = cmd_session_events_report(args)
        assert rc == 1

    @pytest.mark.asyncio
    async def test_events_emitted_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_events_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-evc", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)
        for i in range(4):
            await host.ainvoke("events.emit", {"event_type": "x", "source": "s"}, correlation={"correlation_id": "cli-evc-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-evc-1", store=store_path)
        cmd_session_events_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["events_emitted"] == 4

    @pytest.mark.asyncio
    async def test_events_by_type_breakdown(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_events_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-ebt", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)
        await host.ainvoke("events.emit", {"event_type": "order.placed", "source": "s"}, correlation={"correlation_id": "cli-ebt-1"})
        await host.ainvoke("events.emit", {"event_type": "order.placed", "source": "s"}, correlation={"correlation_id": "cli-ebt-1"})
        await host.ainvoke("events.emit", {"event_type": "order.shipped", "source": "s"}, correlation={"correlation_id": "cli-ebt-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-ebt-1", store=store_path)
        cmd_session_events_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["events_by_type"]["order.placed"] == 2
        assert data["events_by_type"]["order.shipped"] == 1

    @pytest.mark.asyncio
    async def test_events_queried_count(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_events_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-evq", store=store)
        bus = InMemoryEventBus()
        register_event_bus_capability(host, bus)
        bus.emit_event("x", "s", {})
        await host.ainvoke("events.query", {}, correlation={"correlation_id": "cli-evq-1"})
        await host.ainvoke("events.query", {"event_type": "x"}, correlation={"correlation_id": "cli-evq-1"})
        store.close()

        args = argparse.Namespace(session_id="cli-evq-1", store=store_path)
        cmd_session_events_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["events_queried"] == 2


# ── Integration test ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_emit_three_query_one_type(tmp_path):
    """Emit three events of mixed types; query by type returns only the matching ones."""
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("int-evt", store=store)
    bus = InMemoryEventBus()
    register_event_bus_capability(host, bus)

    await host.ainvoke("events.emit", {"event_type": "order.placed", "source": "orders", "data": {"id": "o1"}}, correlation={"correlation_id": "int-001"})
    await host.ainvoke("events.emit", {"event_type": "order.placed", "source": "orders", "data": {"id": "o2"}}, correlation={"correlation_id": "int-001"})
    await host.ainvoke("events.emit", {"event_type": "order.shipped", "source": "fulfillment", "data": {"id": "o1"}}, correlation={"correlation_id": "int-001"})

    result = await host.ainvoke("events.query", {"event_type": "order.placed"}, correlation={"correlation_id": "int-001"})
    assert result.success
    query_result = result.data
    assert query_result["event_count"] == 2
    assert all(e["event_type"] == "order.placed" for e in query_result["events"])

    # Verify data_hash in evidence, not raw data
    events = host.replay("int-001")
    emitted_events = [e for e in events if e["event_type"] == "domain_event_emitted"]
    assert len(emitted_events) == 3
    for e in emitted_events:
        payload = e.get("payload") or {}
        assert "data" not in payload
        assert payload.get("data_hash", "").startswith("sha256:")

    store.close()
