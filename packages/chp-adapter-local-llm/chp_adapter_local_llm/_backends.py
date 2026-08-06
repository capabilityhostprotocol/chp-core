"""Backends for LocalLLMAdapter — compose through chp.adapters.http.

No direct HTTP client: each backend routes calls via
``ctx.ainvoke("chp.adapters.http.request", ...)`` so HTTP is governed by the
transport adapter (retries + circuit breaking) and this module stays
conformance-clean. The adapter depends only on the LocalLLMBackend protocol.
"""

from __future__ import annotations

from typing import Any, Protocol

_HTTP_CAP = "chp.adapters.http.request"
PROBE_TIMEOUT = 3.0


class LocalLLMBackend(Protocol):
    async def list_models(self) -> list[dict[str, Any]]: ...
    async def model_info(self, model: str) -> dict[str, Any]: ...
    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]: ...
    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]: ...


class _ComposedBackend:
    """Shared HTTP composition: every call goes through chp.adapters.http."""

    def __init__(self, base_url: str, timeout: float, ctx: Any) -> None:
        self._url = base_url.rstrip("/")
        self._timeout = timeout
        self._ctx = ctx

    async def _http(self, method: str, path: str, json_body: dict | None = None) -> dict:
        req: dict[str, Any] = {"method": method, "url": f"{self._url}{path}", "timeout": self._timeout}
        if json_body is not None:
            req["json_body"] = json_body
        result = await self._ctx.ainvoke(_HTTP_CAP, req)
        if not getattr(result, "success", False):
            raise RuntimeError(
                f"local_llm transport error ({getattr(result, 'error', 'http adapter unavailable')})"
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            # surface the backend's own reason (ollama/llama.cpp put it in json.error or the body) —
            # without it a tools-schema 400 is undiagnosable.
            body = data.get("json") or data.get("text") or data.get("body") or ""
            reason = body.get("error") if isinstance(body, dict) else str(body)
            detail = f": {str(reason)[:300]}" if reason else ""
            raise RuntimeError(f"local_llm HTTP {status} for {method} {path}{detail}")
        return data.get("json") or {}


# Ollama puts generation params under "options"; tools/think/keep_alive stay top-level.
# Passing them top-level (the old bug) makes Ollama silently ignore temperature/num_ctx.
_OLLAMA_OPTION_KEYS = ("temperature", "num_ctx", "top_p", "top_k", "seed", "stop", "repeat_penalty")


def _ollama_body(base: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    opts: dict[str, Any] = dict(kwargs.pop("options", None) or {})
    if "max_tokens" in kwargs:
        opts["num_predict"] = kwargs.pop("max_tokens")
    for k in _OLLAMA_OPTION_KEYS:
        if k in kwargs:
            opts[k] = kwargs.pop(k)
    if opts:
        base["options"] = opts
    base.update(kwargs)  # remaining: tools, think, keep_alive, format, ...
    return base


class _OllamaBackend(_ComposedBackend):
    async def list_models(self) -> list[dict[str, Any]]:
        return (await self._http("GET", "/api/tags")).get("models", [])

    async def model_info(self, model: str) -> dict[str, Any]:
        return await self._http("POST", "/api/show", {"name": model})

    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        body = _ollama_body({"model": model, "prompt": prompt, "stream": False}, kwargs)
        return await self._http("POST", "/api/generate", body)

    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]:
        body = _ollama_body({"model": model, "messages": messages, "stream": False}, kwargs)
        return await self._http("POST", "/api/chat", body)


def _openai_body(base: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Map the adapter's semantic params to OpenAI top-level; drop Ollama-only keys."""
    opts = kwargs.pop("options", None) or {}
    if "num_predict" in opts and "max_tokens" not in kwargs:
        kwargs["max_tokens"] = opts["num_predict"]
    if "temperature" in opts and "temperature" not in kwargs:
        kwargs["temperature"] = opts["temperature"]
    for k in ("num_ctx", "think", "keep_alive", "top_k"):  # not OpenAI params
        kwargs.pop(k, None)
    for k in ("temperature", "max_tokens", "top_p", "tools", "seed", "stop"):
        if k in kwargs:
            base[k] = kwargs.pop(k)
    base.update(kwargs)
    return base


class _LlamaCppBackend(_ComposedBackend):
    """llama.cpp OpenAI-compatible server backend."""

    async def list_models(self) -> list[dict[str, Any]]:
        return (await self._http("GET", "/v1/models")).get("data", [])

    async def model_info(self, model: str) -> dict[str, Any]:
        return await self._http("GET", f"/v1/models/{model}")

    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        body = _openai_body({"model": model, "prompt": prompt}, kwargs)
        data = await self._http("POST", "/v1/completions", body)
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage", {})
        return {
            "response": choice.get("text", ""),
            "prompt_eval_count": usage.get("prompt_tokens", 0),
            "eval_count": usage.get("completion_tokens", 0),
        }

    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]:
        body = _openai_body({"model": model, "messages": messages}, kwargs)
        data = await self._http("POST", "/v1/chat/completions", body)
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage", {})
        return {
            "message": choice.get("message", {}),
            "prompt_eval_count": usage.get("prompt_tokens", 0),
            "eval_count": usage.get("completion_tokens", 0),
        }


async def probe(ctx: Any, url: str, path: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """Probe a backend endpoint for reachability via the http transport."""
    try:
        result = await ctx.ainvoke(_HTTP_CAP, {
            "method": "GET", "url": f"{url.rstrip('/')}{path}", "timeout": timeout,
        })
        return bool(getattr(result, "success", False)) and result.data.get("status_code") == 200
    except Exception:
        return False
