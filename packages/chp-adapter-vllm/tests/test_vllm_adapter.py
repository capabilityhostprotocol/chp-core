"""Tests for chp-adapter-vllm.

A fake ``chp.adapters.http`` capability is registered on the host, so these
tests exercise the real lego-block composition path (VLLMAdapter → ctx.ainvoke
→ http.request) with no vLLM server and no HTTP library.
"""

from __future__ import annotations

import asyncio
from typing import Any

from chp_adapter_vllm import VLLMAdapter, VLLMConfig
from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Fake http adapter — canned vLLM OpenAI responses
# ---------------------------------------------------------------------------

class FakeHttpAdapter(BaseAdapter):
    adapter_id = "chp.adapters.http"
    adapter_name = "FakeHttp"
    adapter_description = "Canned vLLM OpenAI responses for composition tests."
    adapter_category = "execution"

    @capability(
        id="chp.adapters.http.request",
        version="1.0.0",
        description="Fake HTTP request returning canned vLLM payloads by URL path.",
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
        ctx.emit("http_request", {"method": payload["method"], "url": url}, redacted=False)

        if url.endswith("/v1/completions"):
            body = {
                "choices": [{"text": "GENERATED_COMPLETION_TEXT", "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 11, "total_tokens": 18},
            }
        elif url.endswith("/v1/chat/completions"):
            body = {
                "choices": [{"message": {"role": "assistant", "content": "CHAT_REPLY_TEXT"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 5, "total_tokens": 14},
            }
        elif url.endswith("/v1/models"):
            body = {"data": [{"id": "meta-llama/Llama-3.2-1B-Instruct", "owned_by": "vllm"}]}
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


def _make_host(default_model: str = "test-model") -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, FakeHttpAdapter())
    register_adapter(host, VLLMAdapter(VLLMConfig(default_model=default_model)))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


# ---------------------------------------------------------------------------
# VLLMConfig
# ---------------------------------------------------------------------------

class TestVLLMConfig:
    def test_default_base_url(self, monkeypatch):
        monkeypatch.delenv("VLLM_BASE_URL", raising=False)
        assert VLLMConfig().resolved_base_url() == "http://localhost:8092"

    def test_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("VLLM_BASE_URL", "http://vllm:8000")
        assert VLLMConfig().resolved_base_url() == "http://vllm:8000"

    def test_api_key_defaults_to_empty_sentinel(self, monkeypatch):
        monkeypatch.delenv("VLLM_API_KEY", raising=False)
        assert VLLMConfig().resolved_api_key() == "EMPTY"

    def test_model_from_env(self, monkeypatch):
        monkeypatch.setenv("VLLM_MODEL", "org/model")
        assert VLLMConfig().resolved_default_model() == "org/model"


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_returns_text_and_tokens(self):
        result = _invoke(_make_host(), "chp.adapters.vllm.generate", {"prompt": "Hello"})
        assert result.success
        assert result.data["text"] == "GENERATED_COMPLETION_TEXT"
        assert result.data["prompt_tokens"] == 7
        assert result.data["completion_tokens"] == 11
        assert result.data["finish_reason"] == "stop"

    def test_prompt_and_completion_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.vllm.generate", {"prompt": "SECRET_PROMPT_XYZ"})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            blob = str(evt.get("payload", {}))
            assert "SECRET_PROMPT_XYZ" not in blob
            assert "GENERATED_COMPLETION_TEXT" not in blob

    def test_missing_model_raises(self):
        host = _make_host(default_model="")
        result = _invoke(host, "chp.adapters.vllm.generate", {"prompt": "Hello"})
        assert not result.success

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.vllm.generate", {"prompt": "x"})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# chat
# ---------------------------------------------------------------------------

class TestChat:
    def test_returns_message_and_tokens(self):
        result = _invoke(_make_host(), "chp.adapters.vllm.chat", {
            "messages": [{"role": "user", "content": "hi"}],
        })
        assert result.success
        assert result.data["message"]["content"] == "CHAT_REPLY_TEXT"
        assert result.data["prompt_tokens"] == 9
        assert result.data["completion_tokens"] == 5

    def test_message_content_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.vllm.chat", {
            "messages": [{"role": "user", "content": "SECRET_MESSAGE_ABC"}],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            blob = str(evt.get("payload", {}))
            assert "SECRET_MESSAGE_ABC" not in blob
            assert "CHAT_REPLY_TEXT" not in blob


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------

class TestListModels:
    def test_returns_models(self):
        result = _invoke(_make_host(), "chp.adapters.vllm.list_models", {})
        assert result.success
        assert result.data["model_count"] == 1
        assert result.data["models"][0]["id"] == "meta-llama/Llama-3.2-1B-Instruct"


# ---------------------------------------------------------------------------
# Conformance — vLLM adapter imports no HTTP library (composes via router)
# ---------------------------------------------------------------------------

class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_vllm.adapter as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"VLLMAdapter has conformance violations: {violations}"
