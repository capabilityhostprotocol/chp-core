"""SGLangAdapter — SGLang inference server as governed CHP capabilities.

SGLang (https://github.com/sgl-project/sglang) is an inference server optimised
for structured outputs and long-context models. Key advantages over vLLM for
FastContext workloads:

  - Native `qwen` tool-call parser: structured tool_calls in every response,
    no XML-in-content fallback needed.
  - Radix-tree KV cache: shared prefix (system prompt) is cached across turns,
    reducing TTFT for multi-turn scout loops.
  - Better parallel tool-call support per turn (FastContext's core pattern).

Deployment targets:
  - Primary: CUDA/NVIDIA on Linux (see deploy/com.chp.sglang.service)
  - CPU fallback: any platform via `--device cpu` (slow but functional)
  - Mac/Metal: NOT supported by SGLang as of v0.5; use chp-adapter-vllm instead.

Lego-block composition: no HTTP library imported — every call routes through
chp.adapters.http.request so HTTP becomes its own governed evidence chain.

Evidence policy:
  Emitted: model id, prompt/completion token counts, message count, latency.
  NOT emitted: prompt text, completion text, or chat message content.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "sglang_generate_started",
    "sglang_generate_completed",
    "sglang_generate_failed",
    "sglang_chat_started",
    "sglang_chat_completed",
    "sglang_chat_failed",
    "sglang_models_listed",
]

_DEFAULT_BASE_URL = "http://localhost:8093"
_HTTP_CAP = "chp.adapters.http.request"


@dataclass
class SGLangConfig:
    base_url: str = ""
    api_key: str = ""
    default_model: str = ""
    timeout: float = 120.0

    def resolved_base_url(self) -> str:
        return self.base_url or os.environ.get("SGLANG_BASE_URL", _DEFAULT_BASE_URL)

    def resolved_api_key(self) -> str:
        return self.api_key or os.environ.get("SGLANG_API_KEY", "EMPTY")

    def resolved_default_model(self) -> str:
        return self.default_model or os.environ.get("SGLANG_MODEL", "")


class SGLangAdapter(BaseAdapter):
    """SGLang inference server as governed CHP capabilities."""

    adapter_id = "chp.adapters.sglang"
    adapter_name = "SGLang"
    adapter_description = (
        "Text generation and chat from a local SGLang server, composed through "
        "chp.adapters.http as governed CHP capabilities. SGLang provides native "
        "structured tool-call parsing (no XML fallback) and radix-tree KV caching "
        "for efficient multi-turn agentic loops."
    )
    adapter_category = "ai"
    adapter_tags = ["sglang", "generation", "chat", "cuda", "openai", "local"]

    def __init__(self, config: SGLangConfig | None = None) -> None:
        self._config = config or SGLangConfig()

    async def _http(self, ctx: Any, method: str, path: str, json_body: Any | None = None) -> dict:
        base = self._config.resolved_base_url().rstrip("/")
        req: dict[str, Any] = {"method": method, "url": f"{base}{path}", "timeout": self._config.timeout}
        if json_body is not None:
            req["json_body"] = json_body
        api_key = self._config.resolved_api_key()
        if api_key:
            req["headers"] = {"Authorization": f"Bearer {api_key}"}

        result = await ctx.ainvoke(_HTTP_CAP, req)
        if not result.success:
            raise RuntimeError(
                f"SGLang {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            raise RuntimeError(f"SGLang {method} {path} returned HTTP {status}")
        return data

    def _model(self, payload: dict) -> str:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no default_model configured (set SGLANG_MODEL).")
        return model

    # ------------------------------------------------------------------
    # generate
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.sglang.generate",
        version="1.0.0",
        description=(
            "Single-turn text completion via a local SGLang server (OpenAI /v1/completions), "
            "composed through chp.adapters.http. Prompt and completion text are never recorded."
        ),
        category="ai",
        provider="sglang",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Model id served by SGLang"},
                "prompt": {"type": "string", "minLength": 1},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 32768, "default": 256},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0, "default": 0.7},
                "top_p": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "stop": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    )
    async def generate(self, ctx: Any, payload: dict) -> dict:
        model = self._model(payload)
        body: dict[str, Any] = {
            "model": model,
            "prompt": payload["prompt"],
            "max_tokens": payload.get("max_tokens", 256),
            "temperature": payload.get("temperature", 0.7),
        }
        if "top_p" in payload:
            body["top_p"] = payload["top_p"]
        if payload.get("stop"):
            body["stop"] = payload["stop"]

        ctx.emit("sglang_generate_started", {"model": model, "max_tokens": body["max_tokens"]}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/completions", body)
        except Exception as exc:
            ctx.emit("sglang_generate_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("sglang_generate_completed", {
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "finish_reason": choice.get("finish_reason"),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "text": choice.get("text", ""),
            "finish_reason": choice.get("finish_reason"),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # chat
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.sglang.chat",
        version="1.0.0",
        description=(
            "Multi-turn chat via a local SGLang server (OpenAI /v1/chat/completions). "
            "SGLang's native qwen tool-call parser returns structured tool_calls — no "
            "XML fallback needed. Message content is never recorded in evidence."
        ),
        category="ai",
        provider="sglang",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string", "enum": ["system", "user", "assistant", "tool"]},
                            "content": {"type": "string"},
                            "tool_call_id": {"type": "string"},
                            "tool_calls": {"type": "array"},
                        },
                        "required": ["role"],
                    },
                    "minItems": 1,
                },
                "tools": {"type": "array", "description": "OpenAI-format tool definitions"},
                "tool_choice": {"type": "string", "default": "auto"},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 32768, "default": 256},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0, "default": 0.7},
                "top_p": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
            "required": ["messages"],
            "additionalProperties": False,
        },
    )
    async def chat(self, ctx: Any, payload: dict) -> dict:
        model = self._model(payload)
        messages: list[dict] = payload["messages"]
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": payload.get("max_tokens", 256),
            "temperature": payload.get("temperature", 0.7),
        }
        if "top_p" in payload:
            body["top_p"] = payload["top_p"]
        if payload.get("tools"):
            body["tools"] = payload["tools"]
            body["tool_choice"] = payload.get("tool_choice", "auto")

        ctx.emit("sglang_chat_started", {"model": model, "message_count": len(messages)}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/chat/completions", body)
        except Exception as exc:
            ctx.emit("sglang_chat_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("sglang_chat_completed", {
            "model": model,
            "message_count": len(messages),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "finish_reason": choice.get("finish_reason"),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "message": choice.get("message", {}),
            "finish_reason": choice.get("finish_reason"),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # list_models
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.sglang.list_models",
        version="1.0.0",
        description="List models served by the local SGLang server (OpenAI /v1/models), via chp.adapters.http.",
        category="ai",
        provider="sglang",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def list_models(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        data = await self._http(ctx, "GET", "/v1/models")
        latency_ms = round((time.monotonic() - t0) * 1000)

        resp = data.get("json") or {}
        models = [{"id": m.get("id"), "owned_by": m.get("owned_by")} for m in (resp.get("data") or [])]
        ctx.emit("sglang_models_listed", {"model_count": len(models), "latency_ms": latency_ms}, redacted=False)
        return {"models": models, "model_count": len(models), "latency_ms": latency_ms}
