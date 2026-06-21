"""LocalLLMAdapter — local LLM inference via Ollama or llama.cpp as CHP capabilities.

Backend auto-detection:
  1. Probe Ollama at ``<ollama_url>/api/tags`` (GET, no auth).
  2. If unreachable, probe llama.cpp at ``<llama_cpp_url>/v1/models``.
  3. Config ``backend="ollama"`` or ``backend="llama_cpp"`` skips probing.

Evidence policy: model name, backend, token counts, and latency are evidenced.
Prompt text and completion text are NEVER emitted in evidence.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from chp_core import BaseAdapter, capability

from ._backends import _OllamaBackend, _LlamaCppBackend, probe

_EMITS = [
    "llm_request",
    "llm_response",
    "llm_error",
]

_DEFAULT_OLLAMA_URL = "http://localhost:11434"
_DEFAULT_LLAMA_CPP_URL = "http://localhost:8080"
_DEFAULT_MODEL = "llama3.2"


# ---------------------------------------------------------------------------
# Injectable backend protocol (for tests)
# ---------------------------------------------------------------------------

class LocalLLMBackend(Protocol):
    async def list_models(self) -> list[dict[str, Any]]: ...
    async def model_info(self, model: str) -> dict[str, Any]: ...
    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]: ...
    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class LocalLLMConfig:
    ollama_url: str = ""
    llama_cpp_url: str = ""
    backend: Literal["auto", "ollama", "llama_cpp"] = "auto"
    default_model: str = _DEFAULT_MODEL
    allowed_models: list[str] | None = None
    timeout: float = 120.0
    _backend: LocalLLMBackend | None = field(default=None, repr=False)

    def resolved_ollama_url(self) -> str:
        return self.ollama_url or os.environ.get("OLLAMA_BASE_URL", _DEFAULT_OLLAMA_URL)

    def resolved_llama_cpp_url(self) -> str:
        return self.llama_cpp_url or os.environ.get("LLAMA_CPP_BASE_URL", _DEFAULT_LLAMA_CPP_URL)


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class LocalLLMAdapter(BaseAdapter):
    """Local LLM inference (Ollama primary / llama.cpp fallback) as CHP capabilities."""

    adapter_id = "chp.adapters.local_llm"
    adapter_name = "LocalLLM"
    adapter_description = "Local LLM inference via Ollama (primary) or llama.cpp (fallback)."
    adapter_category = "ai"
    adapter_tags = ["llm", "ollama", "llama", "inference", "local"]

    def __init__(self, config: LocalLLMConfig | None = None) -> None:
        self._config = config or LocalLLMConfig()
        self.__backend_name: str | None = None  # cached resolved backend name

    def _reset_backend(self) -> None:
        """Force re-probe on the next call (e.g. after a transport failure)."""
        self.__backend_name = None

    async def _resolve_name(self, ctx: Any) -> str:
        if self.__backend_name:
            return self.__backend_name
        cfg = self._config
        if cfg.backend in ("ollama", "llama_cpp"):
            self.__backend_name = cfg.backend
            return cfg.backend
        # auto — probe Ollama first (via the governed http transport)
        if await probe(ctx, cfg.resolved_ollama_url(), "/api/tags", cfg.timeout):
            self.__backend_name = "ollama"
        elif await probe(ctx, cfg.resolved_llama_cpp_url(), "/v1/models", cfg.timeout):
            self.__backend_name = "llama_cpp"
        else:
            raise RuntimeError(
                "No local LLM backend reachable. "
                f"Tried Ollama at {cfg.resolved_ollama_url()} and "
                f"llama.cpp at {cfg.resolved_llama_cpp_url()}. "
                "Set OLLAMA_BASE_URL or LLAMA_CPP_BASE_URL, or start Ollama with 'ollama serve'."
            )
        return self.__backend_name

    async def _backend(self, ctx: Any) -> tuple[LocalLLMBackend, str]:
        if self._config._backend is not None:
            return self._config._backend, "injected"
        name = await self._resolve_name(ctx)
        if name == "ollama":
            return _OllamaBackend(self._config.resolved_ollama_url(), self._config.timeout, ctx), "ollama"
        return _LlamaCppBackend(self._config.resolved_llama_cpp_url(), self._config.timeout, ctx), "llama_cpp"

    def _allowed_model(self, model: str) -> str:
        allowed = self._config.allowed_models
        if allowed is not None and model not in allowed:
            raise ValueError(
                f"Model {model!r} is not in the allowed list. Allowed: {allowed}"
            )
        return model

    @capability(
        id="chp.adapters.local_llm.list_models",
        version="1.0.0",
        description="List models available in the local LLM backend.",
        category="ai",
        provider="local_llm",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def list_models(self, ctx: Any, payload: Any) -> Any:
        backend, backend_name = await self._backend(ctx)
        ctx.emit("llm_request", {"op": "list_models", "backend": backend_name}, redacted=False)
        try:
            t0 = time.monotonic()
            models = await backend.list_models()
            latency_ms = round((time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._reset_backend()
            ctx.emit("llm_error", {"op": "list_models", "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("llm_response", {
            "op": "list_models",
            "backend": backend_name,
            "model_count": len(models),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {"backend": backend_name, "models": [_normalize_model_entry(m, backend_name) for m in models]}

    @capability(
        id="chp.adapters.local_llm.model_info",
        version="1.0.0",
        description="Get metadata for a specific model (parameter count, context length, quantization).",
        category="ai",
        provider="local_llm",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"model": {"type": "string", "minLength": 1}},
            "required": ["model"],
            "additionalProperties": False,
        },
    )
    async def model_info(self, ctx: Any, payload: Any) -> Any:
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        backend, backend_name = await self._backend(ctx)
        ctx.emit("llm_request", {"op": "model_info", "backend": backend_name, "model": model}, redacted=False)
        try:
            t0 = time.monotonic()
            info = await backend.model_info(model)
            latency_ms = round((time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._reset_backend()
            ctx.emit("llm_error", {"op": "model_info", "model": model, "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("llm_response", {
            "op": "model_info", "backend": backend_name, "model": model, "latency_ms": latency_ms,
        }, redacted=False)
        return {"backend": backend_name, "model": model, "info": _normalize_model_info(info, backend_name)}

    @capability(
        id="chp.adapters.local_llm.generate",
        version="1.0.0",
        description="Single-turn text generation. Prompt and completion are NOT recorded in evidence.",
        category="ai",
        provider="local_llm",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "prompt": {"type": "string", "minLength": 1},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    )
    async def generate(self, ctx: Any, payload: Any) -> Any:
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        prompt: str = payload["prompt"]
        opts: dict[str, Any] = {}
        if "temperature" in payload:
            opts["temperature"] = payload["temperature"]
        if "max_tokens" in payload:
            opts["num_predict"] = payload["max_tokens"]
        backend, backend_name = await self._backend(ctx)
        ctx.emit("llm_request", {"op": "generate", "backend": backend_name, "model": model}, redacted=False)
        try:
            t0 = time.monotonic()
            result = await backend.generate(model, prompt, **opts)
            latency_ms = round((time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._reset_backend()
            ctx.emit("llm_error", {"op": "generate", "model": model, "error": str(exc)[:500]}, redacted=False)
            raise
        prompt_tokens = result.get("prompt_eval_count", 0)
        completion_tokens = result.get("eval_count", 0)
        ctx.emit("llm_response", {
            "op": "generate", "backend": backend_name, "model": model,
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }, redacted=False)
        return {
            "backend": backend_name, "model": model,
            "text": result.get("response", ""),
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    @capability(
        id="chp.adapters.local_llm.chat",
        version="1.0.0",
        description="Multi-turn chat with message history. Messages are NOT recorded in evidence.",
        category="ai",
        provider="local_llm",
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
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192},
            },
            "required": ["messages"],
            "additionalProperties": False,
        },
    )
    async def chat(self, ctx: Any, payload: Any) -> Any:
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        messages: list[dict] = payload["messages"]
        opts: dict[str, Any] = {}
        if "temperature" in payload:
            opts["temperature"] = payload["temperature"]
        if "max_tokens" in payload:
            opts["num_predict"] = payload["max_tokens"]
        backend, backend_name = await self._backend(ctx)
        ctx.emit("llm_request", {
            "op": "chat", "backend": backend_name, "model": model, "message_count": len(messages),
        }, redacted=False)
        try:
            t0 = time.monotonic()
            result = await backend.chat(model, messages, **opts)
            latency_ms = round((time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._reset_backend()
            ctx.emit("llm_error", {"op": "chat", "model": model, "error": str(exc)[:500]}, redacted=False)
            raise
        prompt_tokens = result.get("prompt_eval_count", 0)
        completion_tokens = result.get("eval_count", 0)
        ctx.emit("llm_response", {
            "op": "chat", "backend": backend_name, "model": model,
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }, redacted=False)
        return {
            "backend": backend_name, "model": model,
            "message": result.get("message", {}),
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalize_model_entry(raw: dict[str, Any], backend: str) -> dict[str, Any]:
    if backend == "ollama":
        return {
            "name": raw.get("name", ""),
            "size_bytes": raw.get("size"),
            "modified_at": raw.get("modified_at"),
        }
    return {"name": raw.get("id", raw.get("name", "")), "size_bytes": None, "modified_at": None}


def _normalize_model_info(raw: dict[str, Any], backend: str) -> dict[str, Any]:
    if backend == "ollama":
        details = raw.get("details", {})
        params = raw.get("model_info", {})
        return {
            "parameter_size": details.get("parameter_size"),
            "quantization": details.get("quantization_level"),
            "context_length": params.get("llama.context_length"),
            "family": details.get("family"),
        }
    return {"raw": raw}
