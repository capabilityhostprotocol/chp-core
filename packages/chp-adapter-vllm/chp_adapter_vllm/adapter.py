"""VLLMAdapter — Apple Silicon native text generation via a local vLLM server.

Wraps a local vLLM OpenAI-compatible server (the `vllm-metal` plugin runs vLLM
on Apple Silicon with an MLX/Metal backend) as governed CHP capabilities:
generate, chat, and list_models.

Lego-block composition: this adapter imports NO HTTP library. Every call routes
through the multi-capability router via ctx.ainvoke("chp.adapters.http.request"),
so HTTP becomes its own governed evidence chain and the adapter stays
conformance-clean. Production-grade generation backend to complement the
HuggingFace adapter's artifact/registry role.

Evidence policy:
  Emitted: model id, prompt/completion token counts, message count, latency, errors.
  NOT emitted: prompt text, completion text, or chat message content.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "vllm_generate_started",
    "vllm_generate_completed",
    "vllm_generate_failed",
    "vllm_chat_started",
    "vllm_chat_completed",
    "vllm_chat_failed",
    "vllm_models_listed",
]

_DEFAULT_BASE_URL = "http://localhost:8092"
_HTTP_CAP = "chp.adapters.http.request"


@dataclass
class VLLMConfig:
    base_url: str = ""
    api_key: str = ""
    default_model: str = ""
    timeout: float = 120.0

    def resolved_base_url(self) -> str:
        return self.base_url or os.environ.get("VLLM_BASE_URL", _DEFAULT_BASE_URL)

    def resolved_api_key(self) -> str:
        # vLLM accepts any key by default; allow override for secured deployments.
        return self.api_key or os.environ.get("VLLM_API_KEY", "EMPTY")

    def resolved_default_model(self) -> str:
        return self.default_model or os.environ.get("VLLM_MODEL", "")


class VLLMAdapter(BaseAdapter):
    """Apple Silicon native generation via a local vLLM OpenAI-compatible server."""

    adapter_id = "chp.adapters.vllm"
    adapter_name = "vLLM"
    adapter_description = (
        "Text generation and chat from a local vLLM server (vllm-metal / Apple "
        "Silicon), composed through chp.adapters.http as governed CHP capabilities."
    )
    adapter_category = "ai"
    adapter_tags = ["vllm", "generation", "chat", "metal", "openai", "local"]

    def __init__(self, config: VLLMConfig | None = None) -> None:
        self._config = config or VLLMConfig()

    # ------------------------------------------------------------------
    # HTTP composition through the multi-capability router
    # ------------------------------------------------------------------

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
                f"vLLM {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            raise RuntimeError(f"vLLM {method} {path} returned HTTP {status}")
        return data

    def _model(self, payload: dict) -> str:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no default_model configured (set VLLM_MODEL).")
        return model

    # ------------------------------------------------------------------
    # generate
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.vllm.generate",
        version="1.0.0",
        description=(
            "Single-turn text completion via a local vLLM server (OpenAI /v1/completions), "
            "composed through chp.adapters.http. Prompt and completion text are never recorded in evidence."
        ),
        category="ai",
        provider="vllm",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Model id served by vLLM (defaults to configured model)"},
                "prompt": {"type": "string", "minLength": 1},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192, "default": 256},
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

        ctx.emit("vllm_generate_started", {"model": model, "max_tokens": body["max_tokens"]}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/completions", body)
        except Exception as exc:
            ctx.emit("vllm_generate_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("vllm_generate_completed", {
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
        id="chp.adapters.vllm.chat",
        version="1.0.0",
        description=(
            "Multi-turn chat via a local vLLM server (OpenAI /v1/chat/completions), composed "
            "through chp.adapters.http. Message content is never recorded in evidence."
        ),
        category="ai",
        provider="vllm",
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
                            "role": {"type": "string", "enum": ["system", "user", "assistant"]},
                            "content": {"type": "string"},
                        },
                        "required": ["role", "content"],
                    },
                    "minItems": 1,
                },
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192, "default": 256},
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

        ctx.emit("vllm_chat_started", {"model": model, "message_count": len(messages)}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/chat/completions", body)
        except Exception as exc:
            ctx.emit("vllm_chat_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("vllm_chat_completed", {
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
        id="chp.adapters.vllm.list_models",
        version="1.0.0",
        description="List models served by the local vLLM server (OpenAI /v1/models), via chp.adapters.http.",
        category="ai",
        provider="vllm",
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
        ctx.emit("vllm_models_listed", {"model_count": len(models), "latency_ms": latency_ms}, redacted=False)
        return {"models": models, "model_count": len(models), "latency_ms": latency_ms}
