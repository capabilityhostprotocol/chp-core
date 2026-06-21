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
            raise RuntimeError(f"local_llm HTTP {status} for {method} {path}")
        return data.get("json") or {}


class _OllamaBackend(_ComposedBackend):
    async def list_models(self) -> list[dict[str, Any]]:
        return (await self._http("GET", "/api/tags")).get("models", [])

    async def model_info(self, model: str) -> dict[str, Any]:
        return await self._http("POST", "/api/show", {"name": model})

    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "prompt": prompt, "stream": False}
        body.update(kwargs)
        return await self._http("POST", "/api/generate", body)

    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
        body.update(kwargs)
        return await self._http("POST", "/api/chat", body)


class _LlamaCppBackend(_ComposedBackend):
    """llama.cpp OpenAI-compatible server backend."""

    async def list_models(self) -> list[dict[str, Any]]:
        return (await self._http("GET", "/v1/models")).get("data", [])

    async def model_info(self, model: str) -> dict[str, Any]:
        return await self._http("GET", f"/v1/models/{model}")

    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "prompt": prompt}
        body.update(kwargs)
        data = await self._http("POST", "/v1/completions", body)
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage", {})
        return {
            "response": choice.get("text", ""),
            "prompt_eval_count": usage.get("prompt_tokens", 0),
            "eval_count": usage.get("completion_tokens", 0),
        }

    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "messages": messages}
        body.update(kwargs)
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
