"""Tests for v0.4.2 TransformationCapability, InMemoryTextTransformationCapability,
register_transformation_capability, and chp session transformation-report."""

from __future__ import annotations

import hashlib
import io
import json
import sys
from types import SimpleNamespace

import pytest

from chp_core import (
    CapabilityDescriptor,
    InMemoryKeywordRetrievalCapability,
    InMemoryTextIngestionCapability,
    InMemoryTextTransformationCapability,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    TRANSFORMATION_EVIDENCE_TYPES,
    TransformationCapability,
    TransformationRecord,
    TransformationResult,
    register_transformation_capability,
)
from chp_core.cli._session import cmd_session_transformation_report
from chp_core.types import new_id


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def cap():
    return InMemoryTextTransformationCapability()


@pytest.fixture
def tmp_host_and_cap(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("test-transformation", store=store)
    cap = InMemoryTextTransformationCapability()
    register_transformation_capability(host, cap)
    yield host, cap, store
    store.close()


# ── InMemoryTextTransformationCapability ──────────────────────────────────────


class TestInMemoryTextTransformation:
    def test_transform_returns_transformation_result(self, cap):
        result = cap.transform("hello world")
        assert isinstance(result, TransformationResult)

    def test_normalize_lowercases_and_collapses_whitespace(self, cap):
        result = cap.transform("  Hello   WORLD  ", transform_type="normalize")
        assert result.content == "hello world"

    def test_chunk_returns_json_parseable_list(self, cap):
        result = cap.transform("hello\n\nworld", transform_type="chunk")
        chunks = json.loads(result.content)
        assert isinstance(chunks, list)
        assert len(chunks) == 2

    def test_chunk_respects_max_chars_param(self, cap):
        text = "a" * 100
        result = cap.transform(text, transform_type="chunk", params={"max_chars": 30, "separator": ""})
        chunks = json.loads(result.content)
        assert all(len(c) <= 30 for c in chunks)

    def test_redact_removes_email_addresses(self, cap):
        result = cap.transform("contact me at user@example.com", transform_type="redact")
        assert "user@example.com" not in result.content
        assert "[REDACTED_EMAIL]" in result.content

    def test_redact_removes_phone_patterns(self, cap):
        result = cap.transform("call 555-867-5309 now", transform_type="redact")
        assert "555-867-5309" not in result.content
        assert "[REDACTED_PHONE]" in result.content

    def test_unknown_transform_type_raises_value_error(self, cap):
        with pytest.raises(ValueError, match="unsupported transform_type"):
            cap.transform("hello", transform_type="nonexistent")

    def test_input_and_output_hashes_are_sha256(self, cap):
        result = cap.transform("hello world")
        assert result.record.input_hash.startswith("sha256:")
        assert result.record.output_hash.startswith("sha256:")
        assert len(result.record.input_hash) == 7 + 64
        assert len(result.record.output_hash) == 7 + 64

    def test_input_hash_is_correct(self, cap):
        text = "hello world"
        result = cap.transform(text)
        expected = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert result.record.input_hash == expected

    def test_latency_ms_is_non_negative(self, cap):
        result = cap.transform("hello world")
        assert result.latency_ms is not None
        assert result.latency_ms >= 0


# ── TransformationCapability descriptor ──────────────────────────────────────


class TestTransformationCapabilityDescriptor:
    def test_as_capability_descriptor_returns_descriptor(self, cap):
        desc = cap.as_capability_descriptor()
        assert isinstance(desc, CapabilityDescriptor)

    def test_category_is_data_knowledge(self, cap):
        desc = cap.as_capability_descriptor()
        assert desc.category == "data_knowledge"

    def test_emits_includes_transformation_events(self, cap):
        desc = cap.as_capability_descriptor()
        assert "transformation_started" in desc.emits
        assert "transformation_completed" in desc.emits
        assert "transformation_failed" in desc.emits

    def test_custom_capability_id_is_reflected(self):
        custom_cap = InMemoryTextTransformationCapability(capability_id="my.transform")
        desc = custom_cap.as_capability_descriptor()
        assert desc.id == "my.transform"


# ── Evidence emission ─────────────────────────────────────────────────────────


class TestTransformationEvidenceEmission:
    def test_transformation_started_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "transformation_started" in types

    def test_transformation_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "transformation_completed" in types

    def test_execution_started_and_completed_in_chain(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        types = [e["event_type"] for e in host.replay(sid)]
        assert "execution_started" in types
        assert "execution_completed" in types

    def test_transformation_completed_has_hashes_in_payload(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "transformation_completed")
        payload = completed.get("payload") or {}
        assert "input_hash" in payload
        assert "output_hash" in payload
        assert payload["input_hash"].startswith("sha256:")
        assert payload["output_hash"].startswith("sha256:")

    def test_transformation_completed_has_correct_transform_type(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke(
            "transformation.transform",
            {"content": "hello", "transform_type": "normalize"},
            correlation_id=sid,
        )
        events = host.replay(sid)
        completed = next(e for e in events if e["event_type"] == "transformation_completed")
        assert (completed.get("payload") or {}).get("transform_type") == "normalize"

    def test_no_raw_content_in_evidence_payload(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        text = "super secret raw content must never appear in evidence"
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": text}, correlation_id=sid)
        evidence_str = json.dumps(host.replay(sid))
        assert "super secret raw content must never appear in evidence" not in evidence_str

    def test_hash_chain_intact_after_transformation(self, tmp_host_and_cap):
        host, cap, store = tmp_host_and_cap
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        events = store.by_correlation_with_hashes(sid)
        hashes = [e.get("prev_hash") for e in events[1:]]
        assert all(h is not None for h in hashes)

    def test_failed_transform_emits_transformation_failed(self, tmp_path):
        class BrokenTransformation(TransformationCapability):
            capability_id = "transformation.broken"
            capability_version = "0.1.0"

            def transform(self, content, *, transform_type="normalize", params=None):
                raise RuntimeError("backend unavailable")

        store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
        host = LocalCapabilityHost("test-broken", store=store)
        register_transformation_capability(host, BrokenTransformation())
        sid = new_id("sess")
        result = host.invoke("transformation.broken", {"content": "test"}, correlation_id=sid)
        assert not result.success
        types = [e["event_type"] for e in host.replay(sid)]
        assert "transformation_failed" in types
        assert "execution_failed" in types


# ── CLI: chp session transformation-report ───────────────────────────────────


class TestTransformationReportCLI:
    def _run_report(self, store_path: str, session_id: str) -> tuple[int, dict]:
        args = SimpleNamespace(store=store_path, session_id=session_id)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = cmd_session_transformation_report(args)
        finally:
            sys.stdout = old
        return rc, json.loads(out.getvalue())

    def test_returns_0_when_transformation_events_found(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_transformation_capability(host, InMemoryTextTransformationCapability())
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        store.close()

        rc, _ = self._run_report(store_path, sid)
        assert rc == 0

    def test_returns_1_for_session_with_no_transformation_events(self, tmp_path):
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

    def test_output_has_transforms_by_type(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_transformation_capability(host, InMemoryTextTransformationCapability())
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        assert "transforms_by_type" in data

    def test_transforms_by_type_counts_correctly(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_transformation_capability(host, InMemoryTextTransformationCapability())
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "hello", "transform_type": "normalize"}, correlation_id=sid)
        host.invoke("transformation.transform", {"content": "world", "transform_type": "normalize"}, correlation_id=sid)
        host.invoke("transformation.transform", {"content": "a@b.com hi", "transform_type": "redact"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        by_type = data["transforms_by_type"]
        assert by_type.get("normalize") == 2
        assert by_type.get("redact") == 1

    def test_avg_latency_ms_is_float_when_present(self, tmp_path):
        store_path = str(tmp_path / "ev.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-test", store=store)
        register_transformation_capability(host, InMemoryTextTransformationCapability())
        sid = new_id("sess")
        host.invoke("transformation.transform", {"content": "test"}, correlation_id=sid)
        store.close()

        _, data = self._run_report(store_path, sid)
        if data["avg_latency_ms"] is not None:
            assert isinstance(data["avg_latency_ms"], (int, float))


# ── Integration: transform → ingest → retrieve pipeline ─────────────────────


def test_transform_feeds_ingestion_pipeline():
    cap = InMemoryTextTransformationCapability()
    result = cap.transform("  Python  TESTING  patterns  ", transform_type="normalize")
    ingestion_cap = InMemoryTextIngestionCapability()
    ingestion_cap.ingest(result.content, source_id="norm-a")
    retrieval_cap = InMemoryKeywordRetrievalCapability(ingestion_cap.as_retrieval_documents())
    assert retrieval_cap.retrieve("python").result_count > 0
