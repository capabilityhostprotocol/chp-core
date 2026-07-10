"""Governed cloud-spill (proposal 0006): chp.spill.chat replaces the raw
proxy byte pump — gates, evidence bracket, and token accounting included."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.spill import register_spill_capability
from chp_core.types import CorrelationContext, InvocationEnvelope


class _FakeOpenAI(BaseHTTPRequestHandler):
    """A minimal OpenAI-compatible upstream: JSON or SSE per `stream`."""

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for i, tok in enumerate(("Hel", "lo")):
                chunk = {"model": "cloud-1", "choices": [
                    {"index": 0, "delta": {"content": tok}, "finish_reason": None}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            final = {"model": "cloud-1", "choices": [{"index": 0, "delta": {},
                     "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": 7, "completion_tokens": 2}}
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
        else:
            resp = {"model": "cloud-1",
                    "choices": [{"index": 0, "message": {"role": "assistant",
                                 "content": "Hello"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 7, "completion_tokens": 2,
                              "total_tokens": 9}}
            raw = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    def log_message(self, *_):
        return


def _fake_cloud():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _host():
    host = LocalCapabilityHost("spill-test", store=SQLiteEvidenceStore(":memory:"))
    register_spill_capability(host)
    return host


class TestGovernedSpill:
    def test_sync_spill_runs_pipeline_with_usage_evidence(self, monkeypatch):
        server, url = _fake_cloud()
        monkeypatch.setenv("CHP_SPILL_BASE_URL", url)
        try:
            host = _host()
            result = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
                capability_id="chp.spill.chat",
                payload={"model": "cloud-1", "messages": [{"role": "user", "content": "hi"}]},
                correlation=CorrelationContext(correlation_id="corr-spill"))))
            assert result.outcome == "success"
            assert result.data["message"]["content"] == "Hello"
            assert result.data["prompt_tokens"] == 7
            events = host.replay("corr-spill")
            types = [e["event_type"] for e in events]
            assert types == ["execution_started", "http_response", "execution_completed"]
            usage_ev = next(e for e in events if e["event_type"] == "http_response")
            assert usage_ev["payload"]["completion_tokens"] == 2  # token accounting
        finally:
            server.shutdown()
            server.server_close()

    def test_stream_spill_yields_chunks_and_assembles(self, monkeypatch):
        server, url = _fake_cloud()
        monkeypatch.setenv("CHP_SPILL_BASE_URL", url)
        try:
            host = _host()

            async def run():
                chunks, result = [], None
                async for item in host.ainvoke_stream(InvocationEnvelope(
                        capability_id="chp.spill.chat",
                        payload={"model": "cloud-1", "messages": []}, mode="stream",
                        correlation=CorrelationContext(correlation_id="corr-spill-s"))):
                    if "chunk" in item:
                        chunks.append(item["chunk"])
                    else:
                        result = item["result"]
                return chunks, result

            chunks, result = asyncio.run(run())
            assert len(chunks) == 3  # two content deltas + the usage/finish chunk
            assert result.outcome == "success"
            assert result.data["message"]["content"] == "Hello"
            assert result.data["completion_tokens"] == 2
            completed = host.replay("corr-spill-s")[-1]
            assert completed["payload"]["prompt_tokens"] == 7  # lifted usage
        finally:
            server.shutdown()
            server.server_close()

    def test_unconfigured_spill_fails_governed(self, monkeypatch):
        monkeypatch.delenv("CHP_SPILL_BASE_URL", raising=False)
        host = _host()
        result = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="chp.spill.chat", payload={"messages": []},
            correlation=CorrelationContext(correlation_id="corr-nospill"))))
        assert result.outcome == "failure"  # execution_failed evidence, not a crash
        types = [e["event_type"] for e in host.replay("corr-nospill")]
        assert types[-1] == "execution_failed"

    def test_policy_can_block_spill(self, monkeypatch):
        from chp_core.policy import PolicyConfig

        monkeypatch.setenv("CHP_SPILL_BASE_URL", "http://127.0.0.1:9")
        host = LocalCapabilityHost(
            "spill-test", store=SQLiteEvidenceStore(":memory:"),
            policy=PolicyConfig(max_risk_tier="medium"))
        register_spill_capability(host)
        result = asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="chp.spill.chat", payload={"messages": []})))
        assert result.denial.code == "policy_blocked"  # spill is risk=high BY DESIGN
