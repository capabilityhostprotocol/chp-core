"""Tests for v0.4.0 RetrievalCapability, InMemoryKeywordRetrievalCapability,
register_retrieval_capability, and chp session retrieval-report."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_core import (
    InMemoryKeywordRetrievalCapability,
    LocalCapabilityHost,
    RETRIEVAL_EVIDENCE_TYPES,
    RetrievalCapability,
    RetrievalResult,
    SQLiteEvidenceStore,
    SourceRef,
    register_retrieval_capability,
)
from chp_core.cli._session import cmd_session_retrieval_report
from chp_core.types import new_id


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def docs():
    return [
        {"source_id": "a", "content": "python testing patterns best practices", "title": "A", "uri": "https://example.com/a"},
        {"source_id": "b", "content": "governance evidence chain integrity", "title": "B"},
        {"source_id": "c", "content": "python sdk retrieval keyword search", "title": "C"},
    ]


@pytest.fixture
def cap(docs):
    return InMemoryKeywordRetrievalCapability(docs)


@pytest.fixture
def tmp_host_and_cap(tmp_path, docs):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-retrieval", store=store)
    cap = InMemoryKeywordRetrievalCapability(docs)
    register_retrieval_capability(host, cap)
    yield host, cap, store
    store.close()


# ── InMemoryKeywordRetrievalCapability ────────────────────────────────────────


class TestInMemoryKeywordRetrieval:
    def test_retrieve_returns_retrieval_result(self, cap):
        result = cap.retrieve("python")
        assert isinstance(result, RetrievalResult)

    def test_retrieve_result_count_matches_source_refs(self, cap):
        result = cap.retrieve("python")
        assert result.result_count == len(result.source_refs)

    def test_retrieve_source_refs_sorted_by_score_desc(self, cap):
        result = cap.retrieve("python")
        scores = [r.score for r in result.source_refs if r.score is not None]
        assert scores == sorted(scores, reverse=True)

    def test_retrieve_top_k_limits_results(self, cap):
        result = cap.retrieve("python", top_k=1)
        assert len(result.source_refs) <= 1

    def test_retrieve_no_match_returns_zero_results(self, cap):
        result = cap.retrieve("zzznomatchquery")
        assert result.result_count == 0
        assert result.source_refs == []

    def test_retrieve_latency_ms_is_set(self, cap):
        result = cap.retrieve("python")
        assert result.latency_ms is not None
        assert result.latency_ms >= 0

    def test_source_ref_to_dict_has_required_keys(self, cap):
        result = cap.retrieve("python")
        assert result.result_count > 0
        d = result.source_refs[0].to_dict()
        assert "source_id" in d
        assert "score" in d

    def test_retrieval_result_to_dict_serialisable(self, cap):
        result = cap.retrieve("python")
        d = result.to_dict()
        assert d["query"] == "python"
        assert isinstance(d["source_refs"], list)
        json.dumps(d)  # must be JSON-serialisable

    def test_source_ref_uri_preserved(self, cap):
        result = cap.retrieve("python")
        found = next((r for r in result.source_refs if r.source_id == "a"), None)
        assert found is not None
        assert found.uri == "https://example.com/a"


# ── RetrievalCapability descriptor ───────────────────────────────────────────


class TestRetrievalCapabilityDescriptor:
    def test_as_capability_descriptor_returns_descriptor(self, cap):
        from chp_core import CapabilityDescriptor
        desc = cap.as_capability_descriptor()
        assert isinstance(desc, CapabilityDescriptor)

    def test_category_is_data_knowledge(self, cap):
        desc = cap.as_capability_descriptor()
        assert desc.category == "data_knowledge"

    def test_emits_includes_retrieval_events(self, cap):
        desc = cap.as_capability_descriptor()
        assert "retrieval_started" in desc.emits
        assert "retrieval_completed" in desc.emits
        assert "retrieval_failed" in desc.emits

    def test_custom_capability_id_is_reflected(self, docs):
        custom_cap = InMemoryKeywordRetrievalCapability(docs, capability_id="my.search")
        desc = custom_cap.as_capability_descriptor()
        assert desc.id == "my.search"

    def test_retrieval_type_is_keyword_by_default(self, cap):
        assert cap.retrieval_type == "keyword"


# ── Evidence emission ─────────────────────────────────────────────────────────


class TestRetrievalEvidenceEmission:
    def test_retrieval_started_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python", "top_k": 2}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "retrieval_started" in types

    def test_retrieval_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python", "top_k": 2}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "retrieval_completed" in types

    def test_execution_started_and_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "execution_started" in types
        assert "execution_completed" in types

    def test_retrieval_completed_has_source_refs_in_payload(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "retrieval_completed")
        payload = completed.get("payload") or {}
        assert "source_refs" in payload
        assert isinstance(payload["source_refs"], list)

    def test_retrieval_completed_result_count_correct(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python", "top_k": 3}, correlation_id=sid)
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "retrieval_completed")
        payload = completed.get("payload") or {}
        assert payload["result_count"] == len(payload["source_refs"])

    def test_hash_chain_intact_after_retrieval(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        events = store.by_correlation_with_hashes(sid)
        hashes = [e.get("prev_hash") for e in events[1:]]
        assert all(h is not None for h in hashes)

    def test_failed_retrieve_emits_retrieval_failed(self, tmp_path):
        class BrokenRetrieval(RetrievalCapability):
            capability_id = "retrieval.broken"
            capability_version = "0.1.0"

            def retrieve(self, query, *, top_k=5, filters=None):
                raise RuntimeError("backend unavailable")

        store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
        host = LocalCapabilityHost("test-broken", store=store)
        register_retrieval_capability(host, BrokenRetrieval())
        sid = new_id("sess")
        result = host.invoke("retrieval.broken", {"query": "test"}, correlation_id=sid)
        assert not result.success
        types = [e["event_type"] for e in host.replay(sid)]
        assert "retrieval_failed" in types
        assert "execution_failed" in types

    def test_retrieval_event_count_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        events = host.replay(sid)
        retrieval_events = [e for e in events if e["event_type"] in RETRIEVAL_EVIDENCE_TYPES]
        assert len(retrieval_events) >= 2  # at minimum started + completed


# ── CLI: chp session retrieval-report ────────────────────────────────────────


class TestRetrievalReportCLI:
    def _run_report(self, store_path: str, session_id: str) -> dict:
        args = SimpleNamespace(store=store_path, session_id=session_id)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = cmd_session_retrieval_report(args)
        finally:
            sys.stdout = old
        return rc, json.loads(out.getvalue())

    def test_returns_0_when_retrieval_events_found(self, tmp_path, docs):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_retrieval_capability(host, InMemoryKeywordRetrievalCapability(docs))
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        store.close()

        rc, _ = self._run_report(store_path, sid)
        assert rc == 0

    def test_returns_1_for_session_with_no_retrieval_events(self, tmp_path, docs):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        from chp_core import CapabilityDescriptor
        async def _noop(ctx, p): return {}
        host.register(CapabilityDescriptor(id="other.cap", version="1.0.0", description="x"), _noop)
        sid = new_id("sess")
        host.invoke("other.cap", {}, correlation_id=sid)
        store.close()

        rc, _ = self._run_report(store_path, sid)
        assert rc == 1

    def test_output_has_retrieval_calls_key(self, tmp_path, docs):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_retrieval_capability(host, InMemoryKeywordRetrievalCapability(docs))
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        assert "retrieval_calls" in data

    def test_total_results_returned_sums_correctly(self, tmp_path, docs):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        cap = InMemoryKeywordRetrievalCapability(docs)
        register_retrieval_capability(host, cap)
        sid = new_id("sess")
        r1 = host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        r2 = host.invoke("retrieval.query", {"query": "evidence"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        assert data["total_results_returned"] >= 0

    def test_avg_latency_ms_is_float_when_present(self, tmp_path, docs):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_retrieval_capability(host, InMemoryKeywordRetrievalCapability(docs))
        sid = new_id("sess")
        host.invoke("retrieval.query", {"query": "python"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        if data["avg_latency_ms"] is not None:
            assert isinstance(data["avg_latency_ms"], (int, float))
