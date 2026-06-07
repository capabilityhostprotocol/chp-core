"""Tests for chp.invocations.* metrics aggregation — v0.4.5."""

from __future__ import annotations

import json
import pytest

from chp_core import (
    CapabilityMetrics,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    SessionMetricsReport,
    aggregate_session_metrics,
    format_prometheus,
    register_retrieval_capability,
    InMemoryKeywordRetrievalCapability,
)
from chp_core.metrics import _percentile


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_event(event_type: str, capability_id: str = "test.cap", occurred_at: str = "2026-01-01T00:00:00Z") -> dict:
    return {
        "event_type": event_type,
        "payload": {"capability_id": capability_id},
        "occurred_at": occurred_at,
    }


def _make_pair(cap_id: str, start: str, end: str, outcome: str = "execution_completed") -> list[dict]:
    return [
        {"event_type": "execution_started", "payload": {"capability_id": cap_id}, "occurred_at": start},
        {"event_type": outcome, "payload": {"capability_id": cap_id}, "occurred_at": end},
    ]


# ── TestPercentile ─────────────────────────────────────────────────────────────


class TestPercentile:
    def test_single_value(self):
        assert _percentile([5.0], 50) == 5.0

    def test_two_values_median(self):
        result = _percentile([1.0, 3.0], 50)
        assert result == pytest.approx(2.0)

    def test_p95_five_values(self):
        result = _percentile([1.0, 2.0, 3.0, 4.0, 5.0], 95)
        assert result > 4.0


# ── TestAggregateSessionMetrics ───────────────────────────────────────────────


class TestAggregateSessionMetrics:
    def test_empty_events_returns_zero_report(self):
        report = aggregate_session_metrics("sess-0", [])
        assert isinstance(report, SessionMetricsReport)
        assert report.total_invocations == 0
        assert report.total_successes == 0
        assert report.capabilities == {}

    def test_single_success_invocation(self):
        events = _make_pair("cap.a", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.100Z")
        report = aggregate_session_metrics("sess-1", events)
        assert report.total_invocations == 1
        assert report.total_successes == 1
        assert report.total_failures == 0

    def test_single_failure_invocation(self):
        events = _make_pair("cap.a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "execution_failed")
        report = aggregate_session_metrics("sess-2", events)
        assert report.total_failures == 1
        assert report.total_successes == 0

    def test_denied_counted_separately(self):
        events = _make_pair("cap.a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "execution_denied")
        report = aggregate_session_metrics("sess-3", events)
        assert report.capabilities["cap.a"].denied == 1
        assert report.total_successes == 0

    def test_multiple_capabilities_aggregated(self):
        events = (
            _make_pair("cap.a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
            + _make_pair("cap.b", "2026-01-01T00:00:02Z", "2026-01-01T00:00:03Z")
            + _make_pair("cap.b", "2026-01-01T00:00:04Z", "2026-01-01T00:00:05Z")
        )
        report = aggregate_session_metrics("sess-4", events)
        assert report.total_invocations == 3
        assert "cap.a" in report.capabilities
        assert "cap.b" in report.capabilities
        assert report.capabilities["cap.a"].invocations == 1
        assert report.capabilities["cap.b"].invocations == 2

    def test_duration_computed_from_timestamps(self):
        events = _make_pair("cap.a", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:01.000Z")
        report = aggregate_session_metrics("sess-5", events)
        assert report.capabilities["cap.a"].avg_duration_ms == pytest.approx(1000.0, abs=1.0)

    def test_p50_p95_computed_for_multiple_invocations(self):
        events = (
            _make_pair("cap.a", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.100Z")
            + _make_pair("cap.a", "2026-01-01T00:00:01.000Z", "2026-01-01T00:00:01.500Z")
            + _make_pair("cap.a", "2026-01-01T00:00:02.000Z", "2026-01-01T00:00:02.900Z")
        )
        report = aggregate_session_metrics("sess-6", events)
        m = report.capabilities["cap.a"]
        assert m.p50_duration_ms is not None
        assert m.p95_duration_ms is not None
        assert m.p50_duration_ms <= m.p95_duration_ms

    def test_single_invocation_has_no_p50_p95(self):
        events = _make_pair("cap.a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
        report = aggregate_session_metrics("sess-7", events)
        assert report.capabilities["cap.a"].p50_duration_ms is None
        assert report.capabilities["cap.a"].p95_duration_ms is None

    def test_unparseable_timestamps_produce_no_duration(self):
        events = [
            {"event_type": "execution_started", "payload": {"capability_id": "x"}, "occurred_at": "bad"},
            {"event_type": "execution_completed", "payload": {"capability_id": "x"}, "occurred_at": "also-bad"},
        ]
        report = aggregate_session_metrics("sess-8", events)
        assert report.capabilities["x"].avg_duration_ms is None

    def test_session_id_preserved_in_report(self):
        report = aggregate_session_metrics("my-session-99", [])
        assert report.session_id == "my-session-99"

    def test_nested_invocations_counted_per_open(self):
        # Simulate workflow invoking a sub-capability: two starts before first close
        events = [
            {"event_type": "execution_started", "payload": {"capability_id": "workflow.run"}, "occurred_at": "2026-01-01T00:00:00Z"},
            {"event_type": "execution_started", "payload": {"capability_id": "graph.add_entity"}, "occurred_at": "2026-01-01T00:00:01Z"},
            {"event_type": "execution_completed", "payload": {"capability_id": "graph.add_entity"}, "occurred_at": "2026-01-01T00:00:02Z"},
            {"event_type": "execution_completed", "payload": {"capability_id": "workflow.run"}, "occurred_at": "2026-01-01T00:00:03Z"},
        ]
        report = aggregate_session_metrics("sess-9", events)
        assert report.capabilities["workflow.run"].invocations == 1
        assert report.capabilities["graph.add_entity"].invocations == 1
        assert report.total_invocations == 2


# ── TestCapabilityMetrics ──────────────────────────────────────────────────────


class TestCapabilityMetrics:
    def test_to_dict_round_trip(self):
        m = CapabilityMetrics(
            capability_id="test.cap",
            invocations=5, successes=4, failures=1, denied=0,
            avg_duration_ms=42.5, p50_duration_ms=40.0, p95_duration_ms=80.0,
        )
        d = m.to_dict()
        assert d["capability_id"] == "test.cap"
        assert d["invocations"] == 5
        assert d["avg_duration_ms"] == 42.5

    def test_none_duration_fields_in_dict(self):
        m = CapabilityMetrics(
            capability_id="x", invocations=1, successes=1, failures=0, denied=0,
        )
        d = m.to_dict()
        assert d["avg_duration_ms"] is None
        assert d["p50_duration_ms"] is None

    def test_session_metrics_report_to_dict(self):
        m = CapabilityMetrics("c", 2, 2, 0, 0)
        report = SessionMetricsReport(
            session_id="s", total_invocations=2, total_successes=2, total_failures=0,
            capabilities={"c": m},
        )
        d = report.to_dict()
        assert d["session_id"] == "s"
        assert "c" in d["capabilities"]
        assert d["capabilities"]["c"]["invocations"] == 2


# ── TestPrometheusFormat ───────────────────────────────────────────────────────


class TestPrometheusFormat:
    def _make_report(self) -> SessionMetricsReport:
        m = CapabilityMetrics(
            capability_id="retrieval.search",
            invocations=3, successes=2, failures=1, denied=0,
            avg_duration_ms=50.0, p50_duration_ms=45.0, p95_duration_ms=90.0,
        )
        return SessionMetricsReport("s", 3, 2, 1, {"retrieval.search": m})

    def test_contains_chp_invocations_total(self):
        out = format_prometheus(self._make_report())
        assert "chp_invocations_total" in out

    def test_success_and_failure_labels(self):
        out = format_prometheus(self._make_report())
        assert 'outcome="success"' in out
        assert 'outcome="failure"' in out

    def test_denied_label_omitted_when_zero(self):
        out = format_prometheus(self._make_report())
        assert 'outcome="denied"' not in out

    def test_denied_label_present_when_nonzero(self):
        m = CapabilityMetrics("x", 1, 0, 0, 1)
        report = SessionMetricsReport("s", 1, 0, 0, {"x": m})
        out = format_prometheus(report)
        assert 'outcome="denied"' in out

    def test_avg_duration_present(self):
        out = format_prometheus(self._make_report())
        assert "chp_invocations_duration_ms_avg" in out

    def test_p50_p95_present(self):
        out = format_prometheus(self._make_report())
        assert "chp_invocations_duration_ms_p50" in out
        assert "chp_invocations_duration_ms_p95" in out

    def test_capability_id_label_in_output(self):
        out = format_prometheus(self._make_report())
        assert 'capability_id="retrieval.search"' in out

    def test_ends_with_newline(self):
        out = format_prometheus(self._make_report())
        assert out.endswith("\n")

    def test_empty_report_still_has_headers(self):
        report = SessionMetricsReport("s", 0, 0, 0, {})
        out = format_prometheus(report)
        assert "# HELP chp_invocations_total" in out


# ── TestMetricsReportCLI ───────────────────────────────────────────────────────


class TestMetricsReportCLI:
    @pytest.mark.asyncio
    async def test_returns_0_when_invocations_found(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_metrics_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-met", store=store)
        retrieval = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, retrieval)
        await host.ainvoke("retrieval.query", {"query": "test"}, correlation={"correlation_id": "met-1"})
        store.close()

        args = argparse.Namespace(session_id="met-1", store=store_path, format="json")
        rc = cmd_session_metrics_report(args)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_returns_1_for_no_invocations(self, tmp_path):
        import argparse
        from chp_core.cli._session import cmd_session_metrics_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-met-empty", store=store)
        store.close()

        args = argparse.Namespace(session_id="no-such-session", store=store_path, format="json")
        rc = cmd_session_metrics_report(args)
        assert rc == 1

    @pytest.mark.asyncio
    async def test_json_output_has_total_invocations(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_metrics_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-met-cnt", store=store)
        retrieval = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, retrieval)
        for _ in range(3):
            await host.ainvoke("retrieval.query", {"query": "q"}, correlation={"correlation_id": "met-2"})
        store.close()

        args = argparse.Namespace(session_id="met-2", store=store_path, format="json")
        cmd_session_metrics_report(args)
        data = json.loads(capsys.readouterr().out)
        assert data["total_invocations"] == 3

    @pytest.mark.asyncio
    async def test_prometheus_format_output(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_metrics_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-met-prom", store=store)
        retrieval = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, retrieval)
        await host.ainvoke("retrieval.query", {"query": "q"}, correlation={"correlation_id": "met-3"})
        store.close()

        args = argparse.Namespace(session_id="met-3", store=store_path, format="prometheus")
        cmd_session_metrics_report(args)
        out = capsys.readouterr().out
        assert "chp_invocations_total" in out

    @pytest.mark.asyncio
    async def test_capabilities_keyed_by_capability_id(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._session import cmd_session_metrics_report

        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-met-key", store=store)
        retrieval = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, retrieval)
        await host.ainvoke("retrieval.query", {"query": "q"}, correlation={"correlation_id": "met-4"})
        store.close()

        args = argparse.Namespace(session_id="met-4", store=store_path, format="json")
        cmd_session_metrics_report(args)
        data = json.loads(capsys.readouterr().out)
        assert "retrieval.query" in data["capabilities"]


# ── Integration ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_aggregate_metrics_from_real_invocations(tmp_path):
    """Run 3 real invocations via ainvoke, assert aggregate_session_metrics counts them."""
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("int-met", store=store)
    retrieval = InMemoryKeywordRetrievalCapability([])
    register_retrieval_capability(host, retrieval)

    corr = "int-met-001"
    for _ in range(3):
        await host.ainvoke("retrieval.query", {"query": "hello"}, correlation={"correlation_id": corr})

    events = store.by_correlation(corr)
    store.close()

    report = aggregate_session_metrics(corr, events)
    assert report.total_invocations == 3
    assert report.capabilities["retrieval.query"].invocations == 3
    assert report.capabilities["retrieval.query"].successes == 3

    prom = format_prometheus(report)
    assert "chp_invocations_total" in prom
    assert 'capability_id="retrieval.query"' in prom
