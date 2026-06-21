"""Tests for chp-adapter-messages."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_filesystem import FilesystemAdapter, FilesystemConfig
from chp_adapter_messages import MessagesAdapter, MessagesConfig
from chp_adapter_messages.backends import JSONLBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host(base_dir, include_content=False) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    # filesystem adapter required for backfill_session (ctx.ainvoke lego-block pattern)
    register_adapter(host, FilesystemAdapter(FilesystemConfig(allowed_roots=["/"])))
    config = MessagesConfig(local_base_dir=base_dir, include_content_in_evidence=include_content)
    register_adapter(host, MessagesAdapter(config))
    return host


def _invoke(host, cap_id, payload=None):
    return host.invoke(cap_id, payload or {})


# ---------------------------------------------------------------------------
# JSONLBackend
# ---------------------------------------------------------------------------

class TestJSONLBackend:
    def test_append_and_load(self, tmp_path):
        import asyncio
        backend = JSONLBackend(str(tmp_path))
        asyncio.run(backend.append("sess-1", {"role": "user", "content": "hello"}))
        asyncio.run(backend.append("sess-1", {"role": "assistant", "content": "world"}))
        turns = asyncio.run(backend.load("sess-1"))
        assert len(turns) == 2
        assert turns[0]["role"] == "user"
        assert turns[1]["role"] == "assistant"

    def test_multi_session_isolation(self, tmp_path):
        import asyncio
        backend = JSONLBackend(str(tmp_path))
        asyncio.run(backend.append("sess-A", {"role": "user", "content": "a"}))
        asyncio.run(backend.append("sess-B", {"role": "user", "content": "b"}))
        a = asyncio.run(backend.load("sess-A"))
        b = asyncio.run(backend.load("sess-B"))
        assert len(a) == 1 and len(b) == 1
        assert a[0]["content"] == "a"
        assert b[0]["content"] == "b"

    def test_empty_session_returns_empty_list(self, tmp_path):
        import asyncio
        backend = JSONLBackend(str(tmp_path))
        turns = asyncio.run(backend.load("nonexistent-session"))
        assert turns == []

    def test_list_sessions(self, tmp_path):
        import asyncio
        backend = JSONLBackend(str(tmp_path))
        asyncio.run(backend.append("s1", {"role": "user", "content": "x"}))
        asyncio.run(backend.append("s2", {"role": "user", "content": "y"}))
        sessions = asyncio.run(backend.list_sessions())
        assert sorted(sessions) == ["s1", "s2"]


# ---------------------------------------------------------------------------
# MessagesAdapter — capability round-trips
# ---------------------------------------------------------------------------

class TestMessagesAdapter:
    def test_capabilities_registered(self, tmp_path):
        host = _make_host(str(tmp_path))
        cap_ids = set(host._capabilities.keys())
        assert any("record_turn" in k for k in cap_ids)
        assert any("load_session" in k for k in cap_ids)
        assert any("list_sessions" in k for k in cap_ids)
        assert any("archive_to_remote" in k for k in cap_ids)
        assert any("backfill_session" in k for k in cap_ids)

    def test_record_and_load_round_trip(self, tmp_path):
        host = _make_host(str(tmp_path))
        r = _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "sess-rt",
            "role": "user",
            "content": "hello from round trip",
            "agent": "test-agent",
        })
        assert r.success
        assert r.data["ok"] is True

        loaded = _invoke(host, "chp.adapters.messages.load_session", {"session_id": "sess-rt"})
        assert loaded.success
        assert loaded.data["count"] == 1
        assert loaded.data["turns"][0]["role"] == "user"

    def test_list_sessions(self, tmp_path):
        host = _make_host(str(tmp_path))
        _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "s1", "role": "user", "content": "a",
        })
        _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "s2", "role": "user", "content": "b",
        })
        r = _invoke(host, "chp.adapters.messages.list_sessions")
        assert r.success
        assert r.data["count"] == 2
        assert sorted(r.data["sessions"]) == ["s1", "s2"]

    def test_content_not_in_evidence_when_redacted(self, tmp_path):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        config = MessagesConfig(local_base_dir=str(tmp_path), include_content_in_evidence=False)
        register_adapter(host, MessagesAdapter(config))

        _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "sess-priv",
            "role": "user",
            "content": "secret content",
        })

        # Check no event in the store has "secret content" in payload
        all_rows = store._conn.execute(
            "SELECT payload_json, event_json FROM evidence_events"
        ).fetchall()
        for row in all_rows:
            assert "secret content" not in row["payload_json"]
            assert "secret content" not in row["event_json"]

    def test_content_in_evidence_when_enabled(self, tmp_path):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        config = MessagesConfig(local_base_dir=str(tmp_path), include_content_in_evidence=True)
        register_adapter(host, MessagesAdapter(config))

        _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "sess-public",
            "role": "user",
            "content": "visible content",
        })

        # At least one event must have the content
        all_payloads = [
            row["payload_json"]
            for row in store._conn.execute(
                "SELECT payload_json FROM evidence_events"
            ).fetchall()
        ]
        assert any("visible content" in p for p in all_payloads)

    def test_content_hash_present_in_evidence(self, tmp_path):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        config = MessagesConfig(local_base_dir=str(tmp_path), include_content_in_evidence=False)
        register_adapter(host, MessagesAdapter(config))

        _invoke(host, "chp.adapters.messages.record_turn", {
            "session_id": "sess-hash",
            "role": "assistant",
            "content": "some answer",
        })

        payloads = [
            json.loads(row["payload_json"])
            for row in store._conn.execute(
                "SELECT payload_json FROM evidence_events WHERE event_type = 'conversation_turn'"
            ).fetchall()
        ]
        assert len(payloads) == 1
        assert "content_hash" in payloads[0]
        assert "content" not in payloads[0]

    def test_multiple_turns_accumulate(self, tmp_path):
        host = _make_host(str(tmp_path))
        for i in range(3):
            _invoke(host, "chp.adapters.messages.record_turn", {
                "session_id": "multi",
                "role": "user" if i % 2 == 0 else "assistant",
                "content": f"turn {i}",
            })

        r = _invoke(host, "chp.adapters.messages.load_session", {"session_id": "multi"})
        assert r.data["count"] == 3

    def test_archive_to_remote_no_remote_configured(self, tmp_path):
        host = _make_host(str(tmp_path))
        r = _invoke(host, "chp.adapters.messages.archive_to_remote", {"session_id": "x"})
        assert r.success
        assert r.data["ok"] is False
        assert "No remote host" in r.data["error"]

    def test_backfill_session_parses_transcript(self, tmp_path):
        # Write a minimal Claude Code JSONL transcript with mixed content
        transcript = tmp_path / "test-session-abc123.jsonl"
        lines = [
            # Real human turn
            json.dumps({"message": {"role": "user", "content": [{"type": "text", "text": "lets build something cool"}]}}),
            # Hook output — should be filtered
            json.dumps({"message": {"role": "user", "content": "<user-prompt-submit-hook>hook data</user-prompt-submit-hook>"}}),
            # Another real turn (string content)
            json.dumps({"message": {"role": "user", "content": "lets proceed"}}),
            # Assistant turn — should be skipped
            json.dumps({"message": {"role": "assistant", "content": "Sure thing!"}}),
            # Local command output — should be filtered
            json.dumps({"message": {"role": "user", "content": "<local-command-stdout>output</local-command-stdout>"}}),
        ]
        transcript.write_text("\n".join(lines))

        host = _make_host(str(tmp_path / "messages"))
        r = _invoke(host, "chp.adapters.messages.backfill_session", {
            "transcript_path": str(transcript),
        })
        assert r.success
        assert r.data["ok"] is True
        assert r.data["turns_added"] == 2
        assert r.data["session_id"] == "test-session-abc123"

        loaded = _invoke(host, "chp.adapters.messages.load_session", {"session_id": "test-session-abc123"})
        assert loaded.data["count"] == 2

    def test_backfill_session_skips_duplicates(self, tmp_path):
        transcript = tmp_path / "dedup-session.jsonl"
        transcript.write_text(
            json.dumps({"message": {"role": "user", "content": "hello world"}}) + "\n"
        )
        host = _make_host(str(tmp_path / "messages"))
        # First backfill
        r1 = _invoke(host, "chp.adapters.messages.backfill_session", {"transcript_path": str(transcript)})
        assert r1.data["turns_added"] == 1
        # Second backfill — same transcript, no duplicates
        r2 = _invoke(host, "chp.adapters.messages.backfill_session", {"transcript_path": str(transcript)})
        assert r2.data["turns_added"] == 0
