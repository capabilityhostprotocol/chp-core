"""CHP adapter for Google Gemini (generate_content API)."""

from __future__ import annotations

from typing import Any

from ..decorators import capability
from .model import ModelAdapter


class GeminiAdapter(ModelAdapter):
    """Wraps Google Gemini's generate_content API as a CHP capability.

    Requires ``pip install chp-core[gemini]`` (or ``google-generativeai>=0.5``).

    Usage::

        from chp_core import LocalCapabilityHost, register_adapter
        from chp_core.adapters.gemini import GeminiAdapter

        host = LocalCapabilityHost("my-host")
        register_adapter(host, GeminiAdapter(model="gemini-2.0-flash"))

        result = host.invoke("gemini.generate_content", {
            "contents": "Explain the Capability Host Protocol.",
        }, correlation_id="sess-1")
    """

    adapter_id = "gemini"
    provider = "google"
    default_model = "gemini-2.0-flash"

    def __init__(
        self,
        *,
        model: str = "gemini-2.0-flash",
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
            import google.generativeai as genai
        except ImportError as exc:
            raise ImportError(
                "google-generativeai package is required: pip install chp-core[gemini]"
            ) from exc
        if self._api_key:
            genai.configure(api_key=self._api_key)
        self._client = genai.GenerativeModel(self._model)
        return self._client

    @capability(
        id="gemini.generate_content",
        version="1.0.0",
        description="Generate content via the Google Gemini API.",
    )
    def generate_content(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._get_client()
        model_id = payload.get("model") or self._model
        prompt_hash = self._prompt_hash(payload) if not self.capture_prompts else ""

        self._emit_model_started(ctx, model_id, prompt_hash)
        t0 = self._now_ms()

        contents = payload.get("contents", "")
        kwargs = {k: v for k, v in payload.items() if k not in ("model", "contents")}
        response = client.generate_content(contents, **kwargs)

        latency_ms = self._now_ms() - t0
        usage_metadata = getattr(response, "usage_metadata", None)
        usage = {
            "prompt_tokens": getattr(usage_metadata, "prompt_token_count", 0),
            "completion_tokens": getattr(usage_metadata, "candidates_token_count", 0),
        }
        candidates = getattr(response, "candidates", [])
        finish_reason = "unknown"
        if candidates:
            fr = getattr(candidates[0], "finish_reason", None)
            if fr is not None:
                finish_reason = str(fr)
        self._emit_model_completed(ctx, model_id, usage, finish_reason, latency_ms)

        return {
            "text": response.text if hasattr(response, "text") else "",
            "model": model_id,
            "finish_reason": finish_reason,
            "usage": usage,
        }
