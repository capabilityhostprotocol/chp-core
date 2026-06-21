"""Tests for chp_adapter_sglang.

No live server needed: FakeCtx intercepts ctx.ainvoke() calls and
returns scripted HTTP responses matching SGLang's OpenAI-compatible API.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from chp_adapter_sglang import SGLangAdapter, SGLangConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeResult:
    success: bool
    data: Any = None
    error: Any = None
    outcome: str = "success"


class FakeCtx:
    def __init__(self, responses: list[FakeResult] | None = None) -> None:
        self._queue: list[FakeResult] = list(responses or [])
        self.emitted: list[tuple[str, dict]] = []
        self.invoked: list[tuple[str, dict]] = []

    def emit(self, event_type: str, payload: dict, redacted: bool = False) -> None:
        self.emitted.append((event_type, payload))

    async def ainvoke(self, capability_id: str, payload: dict, **_kw) -> FakeResult:
        self.invoked.append((capability_id, payload))
        if self._queue:
            return self._queue.pop(0)
        return FakeResult(success=True, data={"status_code": 200, "json": {}})


def _http_ok(json_body: dict) -> FakeResult:
    return FakeResult(success=True, data={"status_code": 200, "json": json_body})


def _completions_resp(text: str, model: str = "fastcontext",
                      prompt_tokens: int = 10, completion_tokens: int = 5) -> FakeResult:
    return _http_ok({
        "model": model,
        "choices": [{"text": text, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
    })


def _chat_resp(content: str, model: str = "fastcontext",
               prompt_tokens: int = 20, completion_tokens: int = 10,
               tool_calls: list | None = None) -> FakeResult:
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return _http_ok({
        "model": model,
        "choices": [{"message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
    })


def _models_resp(model_ids: list[str]) -> FakeResult:
    return _http_ok({
        "data": [{"id": mid, "owned_by": "sglang"} for mid in model_ids],
    })


# ---------------------------------------------------------------------------
# 1. Shaping
# ---------------------------------------------------------------------------

class TestShaping:
    def test_three_capabilities(self):
        ids = {c.descriptor.id for c in SGLangAdapter().capabilities()}
        assert ids == {
            "chp.adapters.sglang.generate",
            "chp.adapters.sglang.chat",
            "chp.adapters.sglang.list_models",
        }

    def test_adapter_id(self):
        assert SGLangAdapter().adapter_id == "chp.adapters.sglang"

    def test_generate_requires_prompt(self):
        cap = {c.descriptor.id: c.descriptor for c in SGLangAdapter().capabilities()}
        assert "prompt" in cap["chp.adapters.sglang.generate"].input_schema["required"]

    def test_chat_requires_messages(self):
        cap = {c.descriptor.id: c.descriptor for c in SGLangAdapter().capabilities()}
        assert "messages" in cap["chp.adapters.sglang.chat"].input_schema["required"]

    def test_default_port_8093(self):
        assert SGLangConfig().resolved_base_url() == "http://localhost:8093"

    def test_generate_medium_risk(self):
        cap = {c.descriptor.id: c.descriptor for c in SGLangAdapter().capabilities()}
        assert cap["chp.adapters.sglang.generate"].risk == "medium"

    def test_list_models_low_risk(self):
        cap = {c.descriptor.id: c.descriptor for c in SGLangAdapter().capabilities()}
        assert cap["chp.adapters.sglang.list_models"].risk == "low"


# ---------------------------------------------------------------------------
# 2. generate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGenerate:
    def _run(self, ctx, prompt="hello", model="fastcontext", **kw):
        adapter = SGLangAdapter(SGLangConfig(default_model=model))
        return asyncio.run(adapter.generate(ctx, {"prompt": prompt, **kw}))

    def test_returns_text(self):
        ctx = FakeCtx([_completions_resp("world")])
        result = self._run(ctx)
        assert result["text"] == "world"
        assert result["finish_reason"] == "stop"

    def test_emits_started_and_completed(self):
        ctx = FakeCtx([_completions_resp("hi")])
        self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "sglang_generate_started" in types
        assert "sglang_generate_completed" in types

    def test_token_counts_in_result(self):
        ctx = FakeCtx([_completions_resp("hi", prompt_tokens=15, completion_tokens=7)])
        result = self._run(ctx)
        assert result["prompt_tokens"] == 15
        assert result["completion_tokens"] == 7

    def test_routes_through_http_cap(self):
        ctx = FakeCtx([_completions_resp("ok")])
        self._run(ctx)
        cap_ids = [inv[0] for inv in ctx.invoked]
        assert all(cid == "chp.adapters.http.request" for cid in cap_ids)

    def test_posts_to_v1_completions(self):
        ctx = FakeCtx([_completions_resp("ok")])
        self._run(ctx)
        url = ctx.invoked[0][1]["url"]
        assert "/v1/completions" in url

    def test_http_error_emits_failed(self):
        ctx = FakeCtx([FakeResult(success=False, error="timeout")])
        with pytest.raises(RuntimeError):
            self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "sglang_generate_failed" in types

    def test_no_model_raises_value_error(self):
        ctx = FakeCtx([_completions_resp("ok")])
        adapter = SGLangAdapter(SGLangConfig())  # no default_model
        with pytest.raises(ValueError, match="No model"):
            asyncio.run(adapter.generate(ctx, {"prompt": "hi"}))

    def test_stop_tokens_forwarded(self):
        ctx = FakeCtx([_completions_resp("ok")])
        self._run(ctx, stop=["<end>"])
        body = ctx.invoked[0][1]["json_body"]
        assert body["stop"] == ["<end>"]

    def test_latency_ms_present(self):
        ctx = FakeCtx([_completions_resp("ok")])
        result = self._run(ctx)
        assert isinstance(result["latency_ms"], int)
        assert result["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# 3. chat
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestChat:
    def _run(self, ctx, messages=None, model="fastcontext", **kw):
        if messages is None:
            messages = [{"role": "user", "content": "hello"}]
        adapter = SGLangAdapter(SGLangConfig(default_model=model))
        return asyncio.run(adapter.chat(ctx, {"messages": messages, **kw}))

    def test_returns_message(self):
        ctx = FakeCtx([_chat_resp("hi there")])
        result = self._run(ctx)
        assert result["message"]["content"] == "hi there"

    def test_emits_started_and_completed(self):
        ctx = FakeCtx([_chat_resp("ok")])
        self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "sglang_chat_started" in types
        assert "sglang_chat_completed" in types

    def test_token_counts_in_result(self):
        ctx = FakeCtx([_chat_resp("ok", prompt_tokens=30, completion_tokens=8)])
        result = self._run(ctx)
        assert result["prompt_tokens"] == 30
        assert result["completion_tokens"] == 8

    def test_tool_calls_forwarded_to_server(self):
        tools = [{"type": "function", "function": {"name": "grep", "parameters": {}}}]
        ctx = FakeCtx([_chat_resp("ok")])
        self._run(ctx, tools=tools)
        body = ctx.invoked[0][1]["json_body"]
        assert body["tools"] == tools
        assert body["tool_choice"] == "auto"

    def test_structured_tool_calls_in_response(self):
        tool_calls = [{"id": "c1", "type": "function",
                       "function": {"name": "grep", "arguments": '{"pattern":"foo"}'}}]
        ctx = FakeCtx([_chat_resp("", tool_calls=tool_calls)])
        result = self._run(ctx)
        assert result["message"]["tool_calls"] == tool_calls

    def test_posts_to_v1_chat_completions(self):
        ctx = FakeCtx([_chat_resp("ok")])
        self._run(ctx)
        url = ctx.invoked[0][1]["url"]
        assert "/v1/chat/completions" in url

    def test_http_error_emits_failed(self):
        ctx = FakeCtx([FakeResult(success=False, error="conn refused")])
        with pytest.raises(RuntimeError):
            self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "sglang_chat_failed" in types

    def test_message_count_in_completed_event(self):
        msgs = [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
        ctx = FakeCtx([_chat_resp("ok")])
        self._run(ctx, messages=msgs)
        completed = [e[1] for e in ctx.emitted if e[0] == "sglang_chat_completed"]
        assert completed[0]["message_count"] == 2

    def test_tool_messages_accepted(self):
        msgs = [
            {"role": "user", "content": "find X"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function",
                "function": {"name": "grep", "arguments": '{}'}}]},
            {"role": "tool", "content": "result", "tool_call_id": "c1"},
        ]
        ctx = FakeCtx([_chat_resp("found it")])
        result = self._run(ctx, messages=msgs)
        assert result["message"]["content"] == "found it"


# ---------------------------------------------------------------------------
# 4. list_models
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestListModels:
    def test_returns_model_list(self):
        ctx = FakeCtx([_models_resp(["fastcontext", "qwen3"])])
        adapter = SGLangAdapter()
        result = asyncio.run(adapter.list_models(ctx, {}))
        assert result["model_count"] == 2
        assert result["models"][0]["id"] == "fastcontext"

    def test_emits_models_listed(self):
        ctx = FakeCtx([_models_resp(["fastcontext"])])
        adapter = SGLangAdapter()
        asyncio.run(adapter.list_models(ctx, {}))
        types = [e[0] for e in ctx.emitted]
        assert "sglang_models_listed" in types

    def test_gets_from_v1_models(self):
        ctx = FakeCtx([_models_resp([])])
        adapter = SGLangAdapter()
        asyncio.run(adapter.list_models(ctx, {}))
        url = ctx.invoked[0][1]["url"]
        assert "/v1/models" in url

    def test_empty_server_returns_zero(self):
        ctx = FakeCtx([_models_resp([])])
        adapter = SGLangAdapter()
        result = asyncio.run(adapter.list_models(ctx, {}))
        assert result["model_count"] == 0
        assert result["models"] == []


# ---------------------------------------------------------------------------
# 5. Config resolution
# ---------------------------------------------------------------------------

class TestConfig:
    def test_env_base_url_override(self, monkeypatch):
        monkeypatch.setenv("SGLANG_BASE_URL", "http://gpu-node:8093")
        assert SGLangConfig().resolved_base_url() == "http://gpu-node:8093"

    def test_explicit_base_url_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("SGLANG_BASE_URL", "http://other:9999")
        assert SGLangConfig(base_url="http://local:8093").resolved_base_url() == "http://local:8093"

    def test_env_model_override(self, monkeypatch):
        monkeypatch.setenv("SGLANG_MODEL", "deepseek-r1")
        assert SGLangConfig().resolved_default_model() == "deepseek-r1"

    def test_default_api_key_is_empty_sentinel(self):
        assert SGLangConfig().resolved_api_key() == "EMPTY"
