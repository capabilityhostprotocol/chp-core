"""CHP adapter for Anthropic Claude (messages API)."""

from __future__ import annotations

from typing import Any

from ..decorators import capability
from .model import ModelAdapter


class ClaudeAdapter(ModelAdapter):
    """Wraps Anthropic's messages API as a CHP capability.

    Requires ``pip install chp-core[claude]`` (or ``anthropic>=0.30``).

    Usage::

        from chp_core import LocalCapabilityHost, register_adapter
        from chp_core.adapters.claude import ClaudeAdapter

        host = LocalCapabilityHost("my-host")
        register_adapter(host, ClaudeAdapter(model="claude-opus-4-5"))

        result = host.invoke("claude.messages.create", {
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1024,
        }, correlation_id="sess-1")
    """

    adapter_id = "claude"
    provider = "anthropic"
    default_model = "claude-opus-4-5"

    def __init__(
        self,
        *,
        model: str = "claude-opus-4-5",
        api_key: str | None = None,
        client: Any = None,
        capture_prompts: bool = False,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._client = client
        self.capture_prompts = capture_prompts

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required: pip install chp-core[claude]"
            ) from exc
        self._client = anthropic.Anthropic(
            **({"api_key": self._api_key} if self._api_key else {})
        )
        return self._client

    @capability(
        id="claude.messages.create",
        version="1.0.0",
        description="Create a message via the Anthropic Claude messages API.",
    )
    def messages_create(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._get_client()
        model_id = payload.get("model") or self._model
        prompt_hash = self._prompt_hash(payload) if not self.capture_prompts else ""

        self._emit_model_started(ctx, model_id, prompt_hash)
        t0 = self._now_ms()

        response = client.messages.create(
            model=model_id,
            messages=payload.get("messages", []),
            max_tokens=payload.get("max_tokens", 1024),
            **{k: v for k, v in payload.items() if k not in ("model", "messages", "max_tokens")},
        )

        latency_ms = self._now_ms() - t0
        usage = {
            "input_tokens": getattr(response.usage, "input_tokens", 0),
            "output_tokens": getattr(response.usage, "output_tokens", 0),
        }
        finish_reason = getattr(response, "stop_reason", "unknown") or "unknown"
        self._emit_model_completed(ctx, model_id, usage, finish_reason, latency_ms)

        return response.model_dump() if hasattr(response, "model_dump") else dict(response)
