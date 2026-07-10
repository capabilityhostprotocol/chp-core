"""Governed streaming (proposal 0006): asyncgen handlers, the shared gate
pipeline, the SSE binding, and the streaming client."""

from __future__ import annotations

import asyncio
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    StreamResult,
)
from chp_core.types import CorrelationContext


def _stream_host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("stream-test", store=SQLiteEvidenceStore(":memory:"))

    async def streamer(_ctx, payload):
        for i in range(3):
            yield {"token": f"t{i}"}
        yield StreamResult({"text": "t0t1t2", "prompt_tokens": 5,
                           "completion_tokens": 3, "model": "fixture"})

    async def broken(_ctx, payload):
        yield {"token": "t0"}
        raise RuntimeError("mid-stream boom")

    async def plain(_ctx, payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(
        id="s.chat", version="1.0.0", description=".", modes=["sync", "stream"]),
        streamer)
    host.register(CapabilityDescriptor(
        id="s.broken", version="1.0.0", description=".", modes=["stream"]),
        broken)
    host.register(CapabilityDescriptor(
        id="s.plain", version="1.0.0", description="."), plain)
    return host


async def _collect(agen):
    items = []
    async for item in agen:
        items.append(item)
    return items


class TestHostStreaming:
    def test_stream_yields_chunks_then_result_with_evidence_bracket(self):
        host = _stream_host()
        items = asyncio.run(_collect(host.ainvoke_stream(InvocationEnvelope(
            capability_id="s.chat", payload={}, mode="stream",
            correlation=CorrelationContext(correlation_id="corr-s1")))))
        chunks = [i["chunk"] for i in items if "chunk" in i]
        assert chunks == [{"token": "t0"}, {"token": "t1"}, {"token": "t2"}]
        result = items[-1]["result"]
        assert result.outcome == "success"
        assert result.data["text"] == "t0t1t2"
        types = [e["event_type"] for e in host.replay("corr-s1")]
        assert types == ["execution_started", "execution_completed"]
        completed = host.replay("corr-s1")[-1]
        assert completed["payload"]["prompt_tokens"] == 5  # usage lifted (§0006)

    def test_sync_invocation_of_stream_capability_collects(self):
        host = _stream_host()
        result = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="s.chat", payload={})))
        assert result.outcome == "success"
        assert result.data == {"text": "t0t1t2", "prompt_tokens": 5,
                               "completion_tokens": 3, "model": "fixture"}

    def test_denial_yields_result_first_with_no_chunks(self):
        host = _stream_host()
        # stream mode against a sync-only capability = gate 4 unsupported_mode
        items = asyncio.run(_collect(host.ainvoke_stream(InvocationEnvelope(
            capability_id="s.plain", payload={}, mode="stream"))))
        assert len(items) == 1 and "result" in items[0]
        assert items[0]["result"].denial.code == "unsupported_mode"

    def test_mid_stream_failure_ends_with_failure_result(self):
        host = _stream_host()
        items = asyncio.run(_collect(host.ainvoke_stream(InvocationEnvelope(
            capability_id="s.broken", payload={}, mode="stream",
            correlation=CorrelationContext(correlation_id="corr-s2")))))
        assert [i for i in items if "chunk" in i]  # at least one chunk got out
        result = items[-1]["result"]
        assert result.outcome == "failure"
        types = [e["event_type"] for e in host.replay("corr-s2")]
        assert types[-1] == "execution_failed"

    def test_stream_mode_undeclared_is_unsupported(self):
        host = _stream_host()
        result = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="s.plain", payload={}, mode="stream")))
        assert result.denial.code == "unsupported_mode"


class TestStreamingWire:
    def _served(self, host):
        from chp_core.http import create_http_server

        server = create_http_server(host, bind="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def test_sse_roundtrip_via_client(self):
        from chp_core.http import RemoteCapabilityHost

        host = _stream_host()
        server, base = self._served(host)
        try:
            remote = RemoteCapabilityHost(base)
            chunks = []
            gen = remote.invoke_stream("s.chat", {"value": 1},
                                       correlation={"correlation_id": "corr-wire"})
            while True:
                try:
                    chunks.append(next(gen))
                except StopIteration as stop:
                    result = stop.value
                    break
            assert chunks == [{"token": "t0"}, {"token": "t1"}, {"token": "t2"}]
            assert result.outcome == "success"
            assert result.data["model"] == "fixture"
        finally:
            server.shutdown()
            server.server_close()

    def test_denial_over_wire_is_plain_json(self):
        from chp_core.http import RemoteCapabilityHost

        host = _stream_host()
        server, base = self._served(host)
        try:
            remote = RemoteCapabilityHost(base)
            gen = remote.invoke_stream("s.plain", {})
            try:
                next(gen)
                raise AssertionError("denial must yield no chunks")
            except StopIteration as stop:
                assert stop.value.denial.code == "unsupported_mode"
        finally:
            server.shutdown()
            server.server_close()
