"""Tests for chp-adapter-tei.

No TEI server and no HTTP library are needed: a fake ``chp.adapters.http``
capability is registered on the host, so these tests exercise the real
lego-block composition path (TEIAdapter → ctx.ainvoke → http.request).
"""

from __future__ import annotations

import asyncio
from typing import Any

from chp_adapter_tei import TEIAdapter, TEIConfig
from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Fake http adapter — stands in for chp.adapters.http on the test host
# ---------------------------------------------------------------------------

class FakeHttpAdapter(BaseAdapter):
    """Minimal chp.adapters.http.request stub returning canned TEI responses."""

    adapter_id = "chp.adapters.http"
    adapter_name = "FakeHttp"
    adapter_description = "Canned HTTP responses for TEI composition tests."
    adapter_category = "execution"

    @capability(
        id="chp.adapters.http.request",
        version="1.0.0",
        description="Fake HTTP request returning canned TEI payloads by URL path.",
        category="execution",
        risk="low",
        emits=["http_request", "http_response"],
        input_schema={
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "json_body": {},
                "timeout": {"type": "number"},
            },
            "required": ["method", "url"],
            "additionalProperties": False,
        },
    )
    async def request(self, ctx: Any, payload: dict) -> dict:
        url = payload["url"]
        json_body = payload.get("json_body") or {}
        ctx.emit("http_request", {"method": payload["method"], "url": url}, redacted=False)

        if url.endswith("/embed"):
            n = len(json_body.get("inputs", []))
            body = [[0.01 * (i + 1)] * 384 for i in range(n)]
        elif url.endswith("/rerank"):
            texts = json_body.get("texts", [])
            body = [{"index": i, "score": round(1.0 - i * 0.1, 4)} for i in range(len(texts))]
        elif url.endswith("/info"):
            body = {
                "model_id": "sentence-transformers/all-MiniLM-L6-v2",
                "model_dtype": "float16",
                "max_input_length": 256,
                "max_batch_tokens": 16384,
                "model_type": {"embedding": {"pooling": "mean"}},
                "version": "1.9.3",
            }
        elif url.endswith("/health"):
            body = None
        else:
            return {"status_code": 404, "json": None, "body": "", "headers": {}}

        ctx.emit("http_response", {"url": url, "status_code": 200}, redacted=False)
        return {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": "",
            "json": body,
            "content_type": "application/json",
            "url": url,
            "duration_ms": 1,
        }


def _make_host() -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, FakeHttpAdapter())
    register_adapter(host, TEIAdapter(TEIConfig()))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


# ---------------------------------------------------------------------------
# TEIConfig
# ---------------------------------------------------------------------------

class TestTEIConfig:
    def test_default_base_url(self, monkeypatch):
        monkeypatch.delenv("TEI_BASE_URL", raising=False)
        assert TEIConfig().resolved_base_url() == "http://localhost:8090"

    def test_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("TEI_BASE_URL", "http://tei.internal:80")
        assert TEIConfig().resolved_base_url() == "http://tei.internal:80"

    def test_explicit_base_url_wins(self, monkeypatch):
        monkeypatch.setenv("TEI_BASE_URL", "http://env:80")
        assert TEIConfig(base_url="http://explicit:90").resolved_base_url() == "http://explicit:90"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("TEI_API_KEY", "secret")
        assert TEIConfig().resolved_api_key() == "secret"


# ---------------------------------------------------------------------------
# embed
# ---------------------------------------------------------------------------

class TestEmbed:
    def test_returns_vectors(self):
        result = _invoke(_make_host(), "chp.adapters.tei.embed", {"inputs": ["a", "b"]})
        assert result.success
        assert result.data["input_count"] == 2
        assert len(result.data["embeddings"]) == 2
        assert result.data["vector_dim"] == 384

    def test_vectors_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.tei.embed", {"inputs": ["secret text"]})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "embeddings" not in p
            assert "vectors" not in p
            assert "inputs" not in p

    def test_normalize_flag_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.tei.embed", {"inputs": ["x"], "normalize": False})
        assert result.success

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.tei.embed", {"inputs": ["x"]})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# rerank
# ---------------------------------------------------------------------------

class TestRerank:
    def test_returns_ranking(self):
        result = _invoke(_make_host(), "chp.adapters.tei.rerank", {
            "query": "best framework",
            "texts": ["CHP", "something", "other"],
        })
        assert result.success
        assert result.data["candidate_count"] == 3
        assert result.data["result_count"] == 3
        assert "index" in result.data["ranking"][0]
        assert "score" in result.data["ranking"][0]

    def test_scores_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.tei.rerank", {
            "query": "q", "texts": ["SENSITIVE_DOC"],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "ranking" not in p
            assert "texts" not in p
            assert "SENSITIVE_DOC" not in str(p)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

class TestInfo:
    def test_returns_model_metadata(self):
        result = _invoke(_make_host(), "chp.adapters.tei.info", {})
        assert result.success
        assert result.data["model_id"] == "sentence-transformers/all-MiniLM-L6-v2"
        assert result.data["max_input_length"] == 256
        assert result.data["model_dtype"] == "float16"


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_healthy(self):
        result = _invoke(_make_host(), "chp.adapters.tei.health", {})
        assert result.success
        assert result.data["healthy"] is True
        assert "base_url" in result.data


# ---------------------------------------------------------------------------
# Conformance — TEI adapter imports no HTTP library (composes via router)
# ---------------------------------------------------------------------------

class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_tei.adapter as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"TEIAdapter has conformance violations: {violations}"
