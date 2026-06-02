"""Small redaction helpers for CHP evidence payloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

DEFAULT_SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
}


def redact_payload(
    value: Any,
    *,
    sensitive_keys: set[str] | None = None,
    replacement: str = "[REDACTED]",
) -> Any:
    """Return a copy of ``value`` with sensitive keys redacted."""

    keys = {key.lower() for key in (sensitive_keys or DEFAULT_SENSITIVE_KEYS)}

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text, keys):
                redacted[key_text] = replacement
            else:
                redacted[key_text] = redact_payload(
                    item,
                    sensitive_keys=keys,
                    replacement=replacement,
                )
        return redacted

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            redact_payload(item, sensitive_keys=keys, replacement=replacement)
            for item in value
        ]

    return value


def _is_sensitive_key(key: str, sensitive_keys: set[str]) -> bool:
    normalized = key.lower()
    return any(sensitive in normalized for sensitive in sensitive_keys)
