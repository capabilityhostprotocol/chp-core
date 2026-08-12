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

# 127.0.0.1 (IPv4), not "localhost": ollama/llama.cpp bind IPv4 by default, but "localhost" can
# resolve to IPv6 ::1 on some hosts — the probe then misses the running server and (with
# auto_start_ollama) spins up a SECOND empty ollama → "model not found" despite models present.
_DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
_DEFAULT_LLAMA_CPP_URL = "http://127.0.0.1:8080"
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
    timeout: float = 300.0  # cold loads of a 14B can exceed 120s; a short timeout aborts the load
    default_num_ctx: int = 8192  # safe floor — Ollama's VRAM-adaptive default (32k) OOMs Metal
    default_keep_alive: str = "5m"  # keep the model resident so callers don't pay cold-start twice
    # adapter-first: self-provision the ollama runtime (install-if-missing + serve) when the
    # probe fails, so pushing this adapter makes a node inference-ready (Linux, root-free).
    auto_start_ollama: bool = True
    models_dir: str = ""  # OLLAMA_MODELS for a self-started ollama (defaults to ollama's own)
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
        if cfg.backend == "ollama":
            # explicit ollama (the deployed config) — self-provision the runtime if it isn't up
            # yet, so a pinned backend still bootstraps on a fresh node (the auto-path hook below
            # would otherwise be skipped by this short-circuit).
            if cfg.auto_start_ollama and not await probe(
                    ctx, cfg.resolved_ollama_url(), "/api/tags", cfg.timeout):
                await self._ensure_ollama(ctx)
            self.__backend_name = "ollama"
            return "ollama"
        if cfg.backend == "llama_cpp":
            self.__backend_name = "llama_cpp"
            return "llama_cpp"
        # auto — probe Ollama first (via the governed http transport)
        if await probe(ctx, cfg.resolved_ollama_url(), "/api/tags", cfg.timeout):
            self.__backend_name = "ollama"
        elif cfg.auto_start_ollama and await self._ensure_ollama(ctx):
            self.__backend_name = "ollama"          # self-provisioned the runtime
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

    async def _ensure_ollama(self, ctx: Any) -> bool:
        """Self-provision the ollama runtime (install-if-missing + serve) then re-probe.
        Adapter-first: pushing this adapter makes a node inference-ready even where ollama
        was never installed. Runs the blocking install/serve off the event loop; best-effort."""
        import asyncio

        from ._ollama_runtime import ensure_ollama
        cfg = self._config
        try:
            ok = await asyncio.to_thread(
                ensure_ollama, cfg.resolved_ollama_url(), models_dir=cfg.models_dir or None)
        except Exception:
            return False
        return bool(ok) and await probe(ctx, cfg.resolved_ollama_url(), "/api/tags", cfg.timeout)

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

    def _gen_params(self, payload: Any) -> dict[str, Any]:
        """Semantic generation params for the backend, with the safety defaults that stop the
        recurring failures: a bounded ``num_ctx`` (Ollama's 32k VRAM-default OOMs Metal) and a
        ``keep_alive`` so the model stays resident instead of cold-loading on every call."""
        params: dict[str, Any] = {
            "num_ctx": payload.get("num_ctx", self._config.default_num_ctx),
            "keep_alive": payload.get("keep_alive", self._config.default_keep_alive),
        }
        if "temperature" in payload:
            params["temperature"] = payload["temperature"]
        if "max_tokens" in payload:
            params["max_tokens"] = payload["max_tokens"]
        return params

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
                "num_ctx": {"type": "integer", "minimum": 256, "maximum": 131072,
                            "description": "context window; defaults to a safe floor to avoid Metal OOM"},
                "keep_alive": {"type": ["string", "integer"],
                               "description": "how long to keep the model resident, e.g. '5m' or 0 to unload"},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    )
    async def generate(self, ctx: Any, payload: Any) -> Any:
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        prompt: str = payload["prompt"]
        opts = self._gen_params(payload)
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
                            "role": {"type": "string",
                                     "enum": ["system", "user", "assistant", "tool"]},
                            "content": {"type": "string"},
                        },
                        "required": ["role", "content"],
                    },
                    "minItems": 1,
                },
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192},
                "num_ctx": {"type": "integer", "minimum": 256, "maximum": 131072,
                            "description": "context window; defaults to a safe floor to avoid Metal OOM"},
                "keep_alive": {"type": ["string", "integer"],
                               "description": "how long to keep the model resident, e.g. '5m' or 0 to unload"},
                "tools": {"type": "array", "items": {"type": "object"},
                          "description": "OpenAI-style function schemas; model returns tool_calls"},
                "think": {"type": "boolean",
                          "description": "toggle a thinking model's CoT (defaults off when tools are present)"},
            },
            "required": ["messages"],
            "additionalProperties": False,
        },
    )
    async def chat(self, ctx: Any, payload: Any) -> Any:
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        messages: list[dict] = payload["messages"]
        opts = self._gen_params(payload)
        # tool-calling: `tools` is a top-level /api/chat param; the model returns structured
        # tool_calls the caller executes. Thinking defaults OFF when tools are present — with
        # thinking on, qwen3+Ollama emit empty output and drop tool_calls (ollama#10976).
        if payload.get("tools"):
            opts["tools"] = payload["tools"]
            opts["think"] = bool(payload.get("think", False))
        elif "think" in payload:
            opts["think"] = bool(payload["think"])
        backend, backend_name = await self._backend(ctx)
        ctx.emit("llm_request", {
            "op": "chat", "backend": backend_name, "model": model, "message_count": len(messages),
            "tool_count": len(payload.get("tools") or []),
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
        msg = result.get("message", {}) or {}
        return {
            "backend": backend_name, "model": model,
            "message": msg,
            "tool_calls": msg.get("tool_calls") or [],
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    @capability(
        id="chp.adapters.local_llm.load",
        version="1.0.0",
        description="Preload (warm) a model into memory and keep it resident. Blocks until loaded.",
        category="ai",
        provider="local_llm",
        risk="low",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "num_ctx": {"type": "integer", "minimum": 256, "maximum": 131072},
                "keep_alive": {"type": ["string", "integer"]},
            },
            "additionalProperties": False,
        },
    )
    async def load(self, ctx: Any, payload: Any) -> Any:
        """Warm a model per Ollama's documented preload (empty prompt + keep_alive), with the
        adapter's long timeout so a cold load isn't aborted mid-flight. Callers warm before
        invoking so tool-calls never hit a cold model under a short client timeout."""
        model = self._allowed_model(payload.get("model") or self._config.default_model)
        backend, backend_name = await self._backend(ctx)
        if backend_name != "ollama":
            return {"backend": backend_name, "model": model, "loaded": True,
                    "note": "no-op: llama.cpp loads its model at server start"}
        ctx.emit("llm_request", {"op": "load", "backend": backend_name, "model": model}, redacted=False)
        try:
            t0 = time.monotonic()
            result = await backend.generate(
                model, "",
                num_ctx=payload.get("num_ctx", self._config.default_num_ctx),
                keep_alive=payload.get("keep_alive", self._config.default_keep_alive),
            )
            latency_ms = round((time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._reset_backend()
            ctx.emit("llm_error", {"op": "load", "model": model, "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("llm_response", {
            "op": "load", "backend": backend_name, "model": model, "latency_ms": latency_ms,
        }, redacted=False)
        return {"backend": backend_name, "model": model,
                "loaded": bool(result.get("done", True)), "latency_ms": latency_ms}


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

        def _mi(suffix: str) -> Any:   # model_info keys are arch-prefixed (qwen3.*, gemma3.*, llama.*)
            return next((v for k, v in params.items() if k.endswith(suffix)), None)
        return {
            "parameter_size": details.get("parameter_size"),
            "quantization": details.get("quantization_level"),
            "context_length": _mi(".context_length"),   # arch-agnostic (was hardcoded llama.*)
            "family": details.get("family"),
            # KV-cache sizing params → a remote node's card can compute a VRAM-fit num_ctx
            "n_layers": _mi(".block_count"),
            "n_heads": _mi(".attention.head_count"),
            "n_kv_heads": _mi(".attention.head_count_kv"),
            "key_length": _mi(".attention.key_length"),
            "embedding_length": _mi(".embedding_length"),
            "capabilities": raw.get("capabilities", []) or [],
        }
    return {"raw": raw}
