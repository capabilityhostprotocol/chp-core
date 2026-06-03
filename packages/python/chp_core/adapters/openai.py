"""CHP adapter for OpenAI chat completions (GPT-4, o3, Azure OpenAI)."""

from __future__ import annotations

from typing import Any

from ..decorators import capability
from .model import ModelAdapter


class OpenAIAdapter(ModelAdapter):
    """Wraps OpenAI's chat completions API as a CHP capability.

    Requires ``pip install chp-core[openai]`` (or ``openai>=1.0``).

    Usage::

        from chp_core import LocalCapabilityHost, register_adapter
        from chp_core.adapters.openai import OpenAIAdapter

        host = LocalCapabilityHost("my-host")
        register_adapter(host, OpenAIAdapter(model="gpt-4o"))

        result = host.invoke("openai.chat.completions.create", {
            "messages": [{"role": "user", "content": "Hello"}],
        }, correlation_id="sess-1")

    For Azure OpenAI, pass ``base_url`` and ``api_key``::

        OpenAIAdapter(
            model="gpt-4",
            base_url="https://<resource>.openai.azure.com/",
            api_key="<azure-key>",
        )
    """

    adapter_id = "openai"
    provider = "openai"
    default_model = "gpt-4o"

    def __init__(
        self,
        *,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str | None = None,
        client: Any = None,
        capture_prompts: bool = False,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url
        self._client = client
        self.capture_prompts = capture_prompts

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "openai package is required: pip install chp-core[openai]"
            ) from exc
        kwargs: dict[str, Any] = {}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._base_url:
            kwargs["base_url"] = self._base_url
        self._client = openai.OpenAI(**kwargs)
        return self._client

    @capability(
        id="openai.chat.completions.create",
        version="1.0.0",
        description="Create a chat completion via the OpenAI API.",
    )
    def chat_completions_create(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._get_client()
        model_id = payload.get("model") or self._model
        prompt_hash = self._prompt_hash(payload) if not self.capture_prompts else ""

        self._emit_model_started(ctx, model_id, prompt_hash)
        t0 = self._now_ms()

        response = client.chat.completions.create(
            model=model_id,
            messages=payload.get("messages", []),
            **{k: v for k, v in payload.items() if k not in ("model", "messages")},
        )

        latency_ms = self._now_ms() - t0
        usage_obj = getattr(response, "usage", None)
        usage = {
            "prompt_tokens": getattr(usage_obj, "prompt_tokens", 0),
            "completion_tokens": getattr(usage_obj, "completion_tokens", 0),
        }
        choices = getattr(response, "choices", [])
        finish_reason = (
            getattr(choices[0], "finish_reason", "unknown") if choices else "unknown"
        ) or "unknown"
        self._emit_model_completed(ctx, model_id, usage, finish_reason, latency_ms)

        return response.model_dump() if hasattr(response, "model_dump") else dict(response)
