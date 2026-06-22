"""MLXAdapter — Apple Silicon native text generation via a local MLX server.

Wraps a local ``mlx_lm.server`` (Apple's MLX framework — the fastest local
inference path on Apple Silicon) as governed CHP capabilities: generate, chat,
list_models, and status. ``mlx_lm.server`` exposes an OpenAI-compatible API
(``/v1/completions``, ``/v1/chat/completions``, ``/v1/models``), so the wire shape
matches the vLLM/local_llm adapters and the gateway can treat MLX as just another
inference owner for capacity-aware routing.

Lego-block composition: this adapter imports NO HTTP library. Every server call
routes through chp.adapters.http via ctx.ainvoke, so HTTP is its own governed
evidence chain and the adapter stays conformance-clean. The ``status`` capability
additionally reports whether the ``mlx`` / ``mlx-lm`` packages are installed on the
host (via importlib, no heavy import) — "is MLX on this machine and serving?"

Evidence policy:
  Emitted: model id, prompt/completion token counts, message count, latency, errors.
  NOT emitted: prompt text, completion text, or chat message content.
"""

from __future__ import annotations

import importlib.util
import os
import time
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "mlx_generate_started",
    "mlx_generate_completed",
    "mlx_generate_failed",
    "mlx_chat_started",
    "mlx_chat_completed",
    "mlx_chat_failed",
    "mlx_models_listed",
    "mlx_status_reported",
]

# mlx_lm.server defaults to :8080, which collides with llama.cpp (probed by the
# local_llm adapter). Default MLX to :8081 and run `mlx_lm.server --port 8081`.
_DEFAULT_BASE_URL = "http://localhost:8081"
_HTTP_CAP = "chp.adapters.http.request"


def _pkg_version(name: str) -> str | None:
    """Installed version of *name*, or None — without importing the package."""
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version(name)
        except PackageNotFoundError:
            return None
    except Exception:
        return None


@dataclass
class MLXConfig:
    base_url: str = ""
    api_key: str = ""
    default_model: str = ""
    timeout: float = 120.0

    def resolved_base_url(self) -> str:
        return self.base_url or os.environ.get("MLX_BASE_URL", _DEFAULT_BASE_URL)

    def resolved_api_key(self) -> str:
        # mlx_lm.server accepts any key; allow override for secured deployments.
        return self.api_key or os.environ.get("MLX_API_KEY", "EMPTY")

    def resolved_default_model(self) -> str:
        return self.default_model or os.environ.get("MLX_MODEL", "")


class MLXAdapter(BaseAdapter):
    """Apple Silicon native generation via a local mlx_lm OpenAI-compatible server."""

    adapter_id = "chp.adapters.mlx"
    adapter_name = "MLX"
    adapter_description = (
        "Text generation and chat from a local mlx_lm.server (Apple Silicon / MLX), "
        "composed through chp.adapters.http as governed CHP capabilities."
    )
    adapter_category = "ai"
    adapter_tags = ["mlx", "generation", "chat", "metal", "apple-silicon", "openai", "local"]

    def __init__(self, config: MLXConfig | None = None) -> None:
        self._config = config or MLXConfig()

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
                f"MLX {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            raise RuntimeError(f"MLX {method} {path} returned HTTP {status}")
        return data

    def _model(self, payload: dict) -> str:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no default_model configured (set MLX_MODEL).")
        return model

    # ------------------------------------------------------------------
    # generate
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.generate",
        version="1.0.0",
        description=(
            "Single-turn text completion via a local mlx_lm server (OpenAI /v1/completions), "
            "composed through chp.adapters.http. Prompt and completion text are never recorded in evidence."
        ),
        category="ai",
        provider="mlx",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Model id served by mlx_lm (defaults to configured model)"},
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

        ctx.emit("mlx_generate_started", {"model": model, "max_tokens": body["max_tokens"]}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/completions", body)
        except Exception as exc:
            ctx.emit("mlx_generate_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("mlx_generate_completed", {
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
        id="chp.adapters.mlx.chat",
        version="1.0.0",
        description=(
            "Multi-turn chat via a local mlx_lm server (OpenAI /v1/chat/completions), composed "
            "through chp.adapters.http. Message content is never recorded in evidence."
        ),
        category="ai",
        provider="mlx",
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

        ctx.emit("mlx_chat_started", {"model": model, "message_count": len(messages)}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/chat/completions", body)
        except Exception as exc:
            ctx.emit("mlx_chat_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("mlx_chat_completed", {
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
        id="chp.adapters.mlx.list_models",
        version="1.0.0",
        description="List models served by the local mlx_lm server (OpenAI /v1/models), via chp.adapters.http.",
        category="ai",
        provider="mlx",
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
        ctx.emit("mlx_models_listed", {"model_count": len(models), "latency_ms": latency_ms}, redacted=False)
        return {"models": models, "model_count": len(models), "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # status — "is MLX on this machine and serving?"
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.status",
        version="1.0.0",
        description=(
            "Report MLX availability on this host: whether the mlx / mlx-lm packages are "
            "installed (and their versions) and whether the local mlx_lm server is reachable. "
            "Low-risk introspection — makes no inference."
        ),
        category="ai",
        provider="mlx",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def status(self, ctx: Any, payload: dict) -> dict:
        # Package availability — importlib.util.find_spec does not import the package.
        mlx_installed = importlib.util.find_spec("mlx") is not None
        mlx_lm_installed = importlib.util.find_spec("mlx_lm") is not None
        base_url = self._config.resolved_base_url()

        server_healthy = False
        model_count = 0
        models: list[dict] = []
        latency_ms: int | None = None
        server_error: str | None = None

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "GET", "/v1/models")
            latency_ms = round((time.monotonic() - t0) * 1000)
            resp = data.get("json") or {}
            models = [{"id": m.get("id"), "owned_by": m.get("owned_by")} for m in (resp.get("data") or [])]
            model_count = len(models)
            server_healthy = True
        except Exception as exc:
            server_error = str(exc)[:300]

        result = {
            "mlx_installed": mlx_installed,
            "mlx_version": _pkg_version("mlx"),
            "mlx_lm_installed": mlx_lm_installed,
            "mlx_lm_version": _pkg_version("mlx-lm"),
            "server_url": base_url,
            "server_healthy": server_healthy,
            "model_count": model_count,
            "models": models,
            "default_model": self._config.resolved_default_model() or None,
            "latency_ms": latency_ms,
            "server_error": server_error,
        }
        ctx.emit("mlx_status_reported", {
            "mlx_installed": mlx_installed,
            "mlx_lm_installed": mlx_lm_installed,
            "server_healthy": server_healthy,
            "model_count": model_count,
        }, redacted=False)
        return result
