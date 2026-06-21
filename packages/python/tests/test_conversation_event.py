"""Tests for ConversationEvent — conversation turns in the evidence chain."""

from __future__ import annotations

import hashlib
import json

import pytest

from chp_core import ConversationEvent, LocalCapabilityHost
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import CorrelationContext, ExecutionEvidence, new_id


def _make_host() -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    return LocalCapabilityHost("test-host", store=store)


# ---------------------------------------------------------------------------
# record_turn basics
# ---------------------------------------------------------------------------

def test_record_turn_returns_conversation_event():
    host = _make_host()
    ev = host.record_turn("corr-1", "user", "Hello world", agent="claude-code")
    assert isinstance(ev, ConversationEvent)
    assert ev.role == "user"
    assert ev.agent == "claude-code"
    assert ev.event_id.startswith("conv_")


def test_record_turn_content_hash():
    host = _make_host()
    text = "Hello world"
    ev = host.record_turn("corr-1", "user", text)
    expected = hashlib.sha256(
        json.dumps(text, sort_keys=True, default=str).encode()
    ).hexdigest()
    assert ev.content_hash == expected


def test_record_turn_content_redacted_by_default():
    host = _make_host()
    ev = host.record_turn("corr-1", "user", "private text")
    assert ev.content is None


def test_record_turn_content_included_when_requested():
    host = _make_host()
    ev = host.record_turn("corr-1", "user", "private text", include_content=True)
    assert ev.content == "private text"


def test_record_turn_word_count():
    host = _make_host()
    ev = host.record_turn("corr-1", "assistant", "one two three four five")
    assert ev.word_count == 5


def test_record_turn_list_content_word_count():
    host = _make_host()
    blocks = [{"type": "text", "text": "hello world"}, {"type": "text", "text": "foo"}]
    ev = host.record_turn("corr-1", "assistant", blocks)
    assert ev.word_count == 3


def test_record_turn_assigned_sequence():
    host = _make_host()
    ev = host.record_turn("corr-1", "user", "hi")
    assert ev.sequence > 0


# ---------------------------------------------------------------------------
# Mixed-chain interleaving
# ---------------------------------------------------------------------------

def test_interleaved_events_in_order():
    """ConversationEvent + ExecutionEvidence share the same sequence space."""
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost("test-host", store=store)
    corr = "corr-mixed"

    turn1 = host.record_turn(corr, "user", "task")
    # Simulate an execution event in the same correlation
    from chp_core.types import (
        AssuranceMetadata, CorrelationContext, ExecutionEvidence, new_id, utc_now
    )
    exec_ev = ExecutionEvidence(
        event_id=new_id("evt"),
        event_type="execution_started",
        invocation_id=new_id("inv"),
        capability_id="chp.test.noop",
        capability_version="1",
        host_id="test-host",
        correlation=CorrelationContext(correlation_id=corr),
        assurance=AssuranceMetadata(),
    )
    store.append(exec_ev)

    turn2 = host.record_turn(corr, "assistant", "result")

    rows = store.by_correlation(corr)
    assert len(rows) == 3
    seqs = [r["sequence"] for r in rows]
    assert seqs == sorted(seqs), "events must be ordered by sequence"

    event_types = [r["event_type"] for r in rows]
    assert event_types[0] == "conversation_turn"
    assert event_types[1] == "execution_started"
    assert event_types[2] == "conversation_turn"


# ---------------------------------------------------------------------------
# verify_chain passes for mixed events
# ---------------------------------------------------------------------------

def test_verify_chain_mixed_events():
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost("test-host", store=store)
    corr = "corr-verify"

    host.record_turn(corr, "user", "hello")
    from chp_core.types import (
        AssuranceMetadata, CorrelationContext, ExecutionEvidence, new_id
    )
    exec_ev = ExecutionEvidence(
        event_id=new_id("evt"),
        event_type="execution_started",
        invocation_id=new_id("inv"),
        capability_id="chp.test.noop",
        capability_version="1",
        host_id="test-host",
        correlation=CorrelationContext(correlation_id=corr),
        assurance=AssuranceMetadata(),
    )
    store.append(exec_ev)
    host.record_turn(corr, "assistant", "world")

    result = store.verify_chain(corr)
    assert result.valid, f"chain broken at seq {result.first_broken_sequence}"
    assert result.event_count == 3
    assert result.verified_count == 3


# ---------------------------------------------------------------------------
# payload_json redaction in store
# ---------------------------------------------------------------------------

def test_conversation_payload_never_stores_content_when_redacted():
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost("test-host", store=store)
    corr = "corr-redact"

    host.record_turn(corr, "user", "secret message", include_content=False)
    rows = store.by_correlation(corr)
    payload = json.loads(
        store._conn.execute(
            "SELECT payload_json FROM evidence_events WHERE correlation_id = ?",
            (corr,),
        ).fetchone()["payload_json"]
    )
    assert "content" not in payload
    assert "content_hash" in payload


def test_conversation_payload_stores_content_when_included():
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost("test-host", store=store)
    corr = "corr-include"

    host.record_turn(corr, "user", "visible message", include_content=True)
    payload = json.loads(
        store._conn.execute(
            "SELECT payload_json FROM evidence_events WHERE correlation_id = ?",
            (corr,),
        ).fetchone()["payload_json"]
    )
    assert payload["content"] == "visible message"
