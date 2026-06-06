"""Tests for v0.4.1 IngestionCapability, InMemoryTextIngestionCapability,
register_ingestion_capability, and chp session ingestion-report."""

from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_core import (
    CapabilityDescriptor,
    INGESTION_EVIDENCE_TYPES,
    IngestionCapability,
    IngestionRecord,
    IngestionResult,
    InMemoryKeywordRetrievalCapability,
    InMemoryTextIngestionCapability,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    register_ingestion_capability,
    register_retrieval_capability,
)
from chp_core.cli._session import cmd_session_ingestion_report
from chp_core.types import new_id


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def cap():
    return InMemoryTextIngestionCapability()


@pytest.fixture
def tmp_host_and_cap(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-ingestion", store=store)
    cap = InMemoryTextIngestionCapability()
    register_ingestion_capability(host, cap)
    yield host, cap, store
    store.close()


# ── InMemoryTextIngestionCapability ───────────────────────────────────────────


class TestInMemoryTextIngestion:
    def test_ingest_returns_ingestion_result(self, cap):
        result = cap.ingest("hello world")
        assert isinstance(result, IngestionResult)

    def test_record_count_is_one(self, cap):
        result = cap.ingest("hello world")
        assert result.record_count == 1
        assert len(result.records) == 1

    def test_content_hash_starts_with_sha256(self, cap):
        result = cap.ingest("hello world")
        assert result.records[0].content_hash.startswith("sha256:")

    def test_content_hash_is_correct(self, cap):
        text = "the quick brown fox"
        result = cap.ingest(text)
        expected = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert result.records[0].content_hash == expected

    def test_byte_count_matches_utf8_length(self, cap):
        text = "café"
        result = cap.ingest(text)
        assert result.records[0].byte_count == len(text.encode("utf-8"))
        assert result.total_bytes == result.records[0].byte_count

    def test_custom_source_id_is_preserved(self, cap):
        result = cap.ingest("content", source_id="my-doc-001")
        assert result.records[0].source_id == "my-doc-001"

    def test_auto_source_id_is_generated(self, cap):
        result = cap.ingest("content")
        assert result.records[0].source_id.startswith("doc_")

    def test_ingestion_record_to_dict_has_required_keys(self, cap):
        result = cap.ingest("hello")
        d = result.records[0].to_dict()
        assert "source_id" in d
        assert "content_hash" in d
        assert "byte_count" in d

    def test_as_retrieval_documents_returns_list(self, cap):
        cap.ingest("python testing", source_id="a", title="A")
        cap.ingest("governance evidence", source_id="b", title="B")
        docs = cap.as_retrieval_documents()
        assert len(docs) == 2
        assert docs[0]["source_id"] == "a"
        assert docs[1]["source_id"] == "b"

    def test_as_retrieval_documents_compatible_with_retrieval_cap(self, cap):
        cap.ingest("python testing patterns", source_id="x")
        retrieval_cap = InMemoryKeywordRetrievalCapability(cap.as_retrieval_documents())
        result = retrieval_cap.retrieve("python")
        assert result.result_count > 0


# ── IngestionCapability descriptor ───────────────────────────────────────────


class TestIngestionCapabilityDescriptor:
    def test_as_capability_descriptor_returns_descriptor(self, cap):
        desc = cap.as_capability_descriptor()
        assert isinstance(desc, CapabilityDescriptor)

    def test_category_is_data_knowledge(self, cap):
        desc = cap.as_capability_descriptor()
        assert desc.category == "data_knowledge"

    def test_emits_includes_ingestion_events(self, cap):
        desc = cap.as_capability_descriptor()
        assert "ingestion_started" in desc.emits
        assert "ingestion_completed" in desc.emits
        assert "ingestion_failed" in desc.emits

    def test_custom_capability_id_is_reflected(self):
        custom_cap = InMemoryTextIngestionCapability(capability_id="my.ingestion")
        desc = custom_cap.as_capability_descriptor()
        assert desc.id == "my.ingestion"


# ── Evidence emission ─────────────────────────────────────────────────────────


class TestIngestionEvidenceEmission:
    def test_ingestion_started_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "ingestion_started" in types

    def test_ingestion_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "ingestion_completed" in types

    def test_execution_started_and_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "execution_started" in types
        assert "execution_completed" in types

    def test_ingestion_completed_has_records_in_payload(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello", "source_id": "doc-001"}, correlation_id=sid)
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "ingestion_completed")
        payload = completed.get("payload") or {}
        assert "records" in payload
        assert isinstance(payload["records"], list)
        assert len(payload["records"]) == 1

    def test_content_hash_present_and_correct_in_evidence(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        text = "the quick brown fox"
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": text}, correlation_id=sid)
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "ingestion_completed")
        record = (completed.get("payload") or {})["records"][0]
        expected = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert record["content_hash"] == expected

    def test_no_raw_content_in_evidence_payload(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        text = "secret raw content should never appear"
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": text}, correlation_id=sid)
        events = host.replay(sid)
        evidence_str = json.dumps(events)
        assert "secret raw content should never appear" not in evidence_str

    def test_hash_chain_intact_after_ingestion(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "test"}, correlation_id=sid)
        events = store.by_correlation_with_hashes(sid)
        hashes = [e.get("prev_hash") for e in events[1:]]
        assert all(h is not None for h in hashes)

    def test_failed_ingest_emits_ingestion_failed(self, tmp_path):
        class BrokenIngestion(IngestionCapability):
            capability_id = "ingestion.broken"
            capability_version = "0.1.0"

            def ingest(self, content, **kwargs):
                raise RuntimeError("backend unavailable")

        store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
        host = LocalCapabilityHost("test-broken", store=store)
        register_ingestion_capability(host, BrokenIngestion())
        sid = new_id("sess")
        result = host.invoke("ingestion.broken", {"content": "test"}, correlation_id=sid)
        assert not result.success
        types = [e["event_type"] for e in host.replay(sid)]
        assert "ingestion_failed" in types
        assert "execution_failed" in types


# ── CLI: chp session ingestion-report ────────────────────────────────────────


class TestIngestionReportCLI:
    def _run_report(self, store_path: str, session_id: str) -> tuple[int, dict]:
        args = SimpleNamespace(store=store_path, session_id=session_id)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = cmd_session_ingestion_report(args)
        finally:
            sys.stdout = old
        return rc, json.loads(out.getvalue())

    def test_returns_0_when_ingestion_events_found(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_ingestion_capability(host, InMemoryTextIngestionCapability())
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello"}, correlation_id=sid)
        store.close()

        rc, _ = self._run_report(store_path, sid)
        assert rc == 0

    def test_returns_1_for_session_with_no_ingestion_events(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)

        async def _noop(ctx, p):
            return {}

        host.register(CapabilityDescriptor(id="other.cap", version="1.0.0", description="x"), _noop)
        sid = new_id("sess")
        host.invoke("other.cap", {}, correlation_id=sid)
        store.close()

        rc, _ = self._run_report(store_path, sid)
        assert rc == 1

    def test_output_has_total_records_ingested(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_ingestion_capability(host, InMemoryTextIngestionCapability())
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "hello"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        assert "total_records_ingested" in data

    def test_total_bytes_ingested_sums_correctly(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_ingestion_capability(host, InMemoryTextIngestionCapability())
        sid = new_id("sess")
        text = "hello world"
        host.invoke("ingestion.ingest", {"content": text}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        assert data["total_bytes_ingested"] == len(text.encode("utf-8"))

    def test_avg_latency_ms_is_float_when_present(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_ingestion_capability(host, InMemoryTextIngestionCapability())
        sid = new_id("sess")
        host.invoke("ingestion.ingest", {"content": "test"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        if data["avg_latency_ms"] is not None:
            assert isinstance(data["avg_latency_ms"], (int, float))


# ── Integration: ingest → retrieve pipeline ───────────────────────────────────


def test_ingest_feeds_retrieval():
    ingestion_cap = InMemoryTextIngestionCapability()
    ingestion_cap.ingest("python testing patterns", title="Doc A", source_id="a")
    ingestion_cap.ingest("governance evidence chain", title="Doc B", source_id="b")

    retrieval_cap = InMemoryKeywordRetrievalCapability(ingestion_cap.as_retrieval_documents())
    result = retrieval_cap.retrieve("python")

    assert result.result_count > 0
    assert result.source_refs[0].source_id == "a"
