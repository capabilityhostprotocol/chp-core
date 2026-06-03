"""Base class for LLM provider adapters."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from . import BaseAdapter


class ModelAdapter(BaseAdapter):
    """Base class for LLM provider adapters.

    Subclasses declare ``provider`` and ``default_model`` and implement a
    ``@capability``-decorated handler that wraps the provider's SDK.

    Set ``capture_prompts=True`` to store full prompt content in evidence
    (off by default — prompts may contain sensitive data).
    """

    provider: str
    default_model: str
    capture_prompts: bool = False

    def _emit_model_started(
        self,
        ctx: Any,
        model_id: str,
        prompt_hash: str,
    ) -> None:
        ctx.emit(
            "model_invocation_started",
            {
                "model_id": model_id,
                "provider": self.provider,
                "prompt_hash": prompt_hash,
            },
            redacted=False,
        )

    def _emit_model_completed(
        self,
        ctx: Any,
        model_id: str,
        usage: dict[str, Any],
        finish_reason: str,
        latency_ms: int,
    ) -> None:
        ctx.emit(
            "model_invocation_completed",
            {
                "model_id": model_id,
                "provider": self.provider,
                "prompt_tokens": usage.get("input_tokens") or usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("output_tokens") or usage.get("completion_tokens", 0),
                "finish_reason": finish_reason,
                "latency_ms": latency_ms,
            },
            redacted=False,
        )

    @staticmethod
    def _prompt_hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:16]

    @staticmethod
    def _now_ms() -> int:
        return int(time.monotonic() * 1000)
