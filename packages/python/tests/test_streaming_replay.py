"""Streaming completion (chp-v0.2.md §13.1, proposal 0012) — chunk-sequence
evidence, idempotent streaming replay, and Last-Event-ID resume-from-offset."""

from __future__ import annotations

import asyncio
import hashlib
import json

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    StreamResult,
)
from chp_core.host import chunk_seq_digest
from chp_core.types import CorrelationContext


def _host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("stream-replay", store=SQLiteEvidenceStore(":memory:"))

    async def streamer(_ctx, _payload):
        for i in range(3):
            yield {"token": f"t{i}"}
        yield StreamResult({"text": "t0t1t2", "prompt_tokens": 5})

    async def plain(_ctx, _payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="s.chat", version="1.0.0", description=".",
                                       modes=["sync", "stream"]), streamer)
    # stream-capable but a NON-generator handler → degrades to one terminal
    # result with no chunks (exercises the zero-chunk-fields byte-compat path).
    host.register(CapabilityDescriptor(id="s.plain", version="1.0.0", description=".",
                                       modes=["sync", "stream"]), plain)
    return host


def _env(inv_id: str, corr: str, cap: str = "s.chat") -> InvocationEnvelope:
    return InvocationEnvelope(capability_id=cap, payload={}, mode="stream",
                             invocation_id=inv_id,
                             correlation=CorrelationContext(correlation_id=corr))


async def _collect(agen):
    return [item async for item in agen]


def _run(host, env, **kw):
    return asyncio.run(_collect(host.ainvoke_stream(env, **kw)))


# ── chp-chunk-seq-v1 ─────────────────────────────────────────────────────────

def test_chunk_seq_digest_deterministic_and_ordered():
    a = [{"token": "t0"}, {"token": "t1"}]
    assert chunk_seq_digest(a) == chunk_seq_digest([{"token": "t0"}, {"token": "t1"}])
    assert chunk_seq_digest(a) != chunk_seq_digest(list(reversed(a)))  # order matters
    expected = hashlib.sha256(
        (json.dumps({"token": "t0"}, sort_keys=True) + "\n"
         + json.dumps({"token": "t1"}, sort_keys=True) + "\n").encode()).hexdigest()
    assert chunk_seq_digest(a) == expected
    assert chunk_seq_digest([]) == hashlib.sha256(b"").hexdigest()  # empty = well-defined


# ── chunk-sequence evidence ──────────────────────────────────────────────────

def test_completed_carries_chunk_seq_evidence():
    host = _host()
    _run(host, _env("inv-1", "c1"))
    completed = [e for e in host.replay("c1") if e["event_type"] == "execution_completed"][0]
    p = completed["payload"]
    assert p["chunk_count"] == 3
    assert p["chunk_seq_digest"] == chunk_seq_digest([{"token": f"t{i}"} for i in range(3)])


def test_non_stream_completion_has_no_chunk_fields():
    """A non-generator (sync-degrade) handler emits no chunk fields — the
    execution_completed payload is byte-identical to pre-0012."""
    host = _host()
    _run(host, _env("inv-p", "cp", cap="s.plain"))
    completed = [e for e in host.replay("cp") if e["event_type"] == "execution_completed"][0]
    assert "chunk_count" not in completed["payload"]
    assert "chunk_seq_digest" not in completed["payload"]


# ── idempotent streaming replay ──────────────────────────────────────────────

def test_retried_stream_replays_recorded_chunks():
    host = _host()
    first = _run(host, _env("inv-r", "cr"))
    first_chunks = [i["chunk"] for i in first if "chunk" in i]
    assert first_chunks == [{"token": f"t{i}"} for i in range(3)]
    assert first[-1]["result"].replayed is False

    # Retry the SAME invocation_id → replay: identical chunks, replayed=True, and
    # NO new lifecycle events (the execution did not re-happen).
    n_events_before = len(host.replay("cr"))
    second = _run(host, _env("inv-r", "cr"))
    assert [i["chunk"] for i in second if "chunk" in i] == first_chunks
    assert second[-1]["result"].replayed is True
    assert len(host.replay("cr")) == n_events_before  # no re-execution events


def test_resume_from_offset():
    host = _host()
    _run(host, _env("inv-o", "co"))  # record chunks 0,1,2
    # Reconnect with Last-Event-ID=1 → resume from chunk 2 only.
    resumed = _run(host, _env("inv-o", "co"), resume_from=1)
    assert [i["chunk"] for i in resumed if "chunk" in i] == [{"token": "t2"}]
    assert resumed[-1]["result"].replayed is True
    # resume_from=-1 (fresh replay) → all chunks.
    full = _run(host, _env("inv-o", "co"), resume_from=-1)
    assert [i["chunk"] for i in full if "chunk" in i] == [{"token": f"t{i}"} for i in range(3)]


def test_over_cap_degrades_to_result_only(monkeypatch):
    monkeypatch.setenv("CHP_STREAM_CACHE_MAX_CHUNKS", "0")  # nothing cached
    host = _host()
    _run(host, _env("inv-cap", "ccap"))
    replay = _run(host, _env("inv-cap", "ccap"))
    # No chunks re-streamed (not cached), but the result still replays idempotently.
    assert [i["chunk"] for i in replay if "chunk" in i] == []
    assert replay[-1]["result"].replayed is True


def test_cli_stream_verify(tmp_path):
    """`chp stream verify` recomputes chp-chunk-seq-v1 and exits 0 on match, 1 on tamper."""
    import argparse

    from chp_core.cli._core import cmd_stream_verify

    deltas = [{"token": "t0"}, {"token": "t1"}]
    good = tmp_path / "cs.json"
    good.write_text(json.dumps({"deltas": deltas, "chunk_seq_digest": chunk_seq_digest(deltas)}))
    assert cmd_stream_verify(argparse.Namespace(file=str(good))) == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"deltas": deltas, "chunk_seq_digest": "0" * 64}))
    assert cmd_stream_verify(argparse.Namespace(file=str(bad))) == 1


def test_sync_replay_unchanged():
    """Dropping the stream exclusion at gate 0 must not change sync replay."""
    host = _host()
    r1 = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="s.plain", payload={}, invocation_id="inv-sync",
        correlation=CorrelationContext(correlation_id="csync"))))
    assert r1.replayed is False
    r2 = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
        capability_id="s.plain", payload={}, invocation_id="inv-sync",
        correlation=CorrelationContext(correlation_id="csync"))))
    assert r2.replayed is True and r2.data == r1.data
