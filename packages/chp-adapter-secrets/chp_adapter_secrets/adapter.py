"""SecretsAdapter — runtime credential injection via CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Secret ``value`` — NEVER in evidence (any backend).
* ``set`` payload ``value`` — NEVER in evidence.
* Only key names, ``found``, ``deleted``, and counts are recorded.

Four capabilities: get, set, delete, list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import sys

from chp_core import BaseAdapter, capability

from .backends import KeychainBackend, MemoryBackend

_EMITS = ["secrets_get", "secrets_set", "secrets_delete", "secrets_list", "secrets_error"]


def _default_backend() -> Any:
    """Durable-by-default backend: macOS Keychain when available, else in-memory.

    The previous default (MemoryBackend) lost all secrets on host restart. On
    darwin we prefer the Keychain so credentials survive restarts; if the
    Keychain is unavailable for any reason we fall back to MemoryBackend rather
    than fail construction.
    """
    if sys.platform == "darwin":
        try:
            return KeychainBackend()
        except Exception:
            return MemoryBackend()
    return MemoryBackend()


@dataclass
class SecretsConfig:
    """Config for SecretsAdapter.

    ``backend`` — any object implementing SecretsBackend protocol. When unset,
    defaults to the macOS Keychain on darwin (durable) and ``MemoryBackend``
    elsewhere.
    """
    backend: Any = None


class SecretsAdapter(BaseAdapter):
    """Inject runtime credentials from env, file, or in-memory backends."""

    adapter_id = "chp.adapters.secrets"
    adapter_name = "Secrets"
    adapter_description = "Runtime credential injection from env/file/memory backends."
    adapter_category = "security"
    adapter_tags = ["secrets", "credentials", "security"]

    def __init__(self, config: SecretsConfig | None = None) -> None:
        self._config = config or SecretsConfig()
        self._backend = self._config.backend or _default_backend()

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.secrets.get",
        version="1.0.0",
        description="Retrieve a secret value by key.",
        category="security",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "minLength": 1},
            },
            "required": ["key"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["secrets"],
    )
    async def get(self, ctx: Any, payload: dict) -> dict:
        key = payload["key"]
        try:
            value = self._backend.get(key)
        except Exception as exc:
            ctx.emit("secrets_error", {"key": key, "reason": str(exc)})
            raise
        found = value is not None
        ctx.emit("secrets_get", {"key": key, "found": found})  # value intentionally excluded
        if not found:
            raise KeyError(f"Secret {key!r} not found")
        return {"key": key, "value": value}  # returned to caller; NOT stored in evidence

    @capability(
        id="chp.adapters.secrets.set",
        version="1.0.0",
        description="Store or update a secret value.",
        category="security",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "minLength": 1},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["secrets"],
    )
    async def set(self, ctx: Any, payload: dict) -> dict:
        key = payload["key"]
        value = payload["value"]
        try:
            self._backend.set(key, value)
        except Exception as exc:
            ctx.emit("secrets_error", {"key": key, "reason": str(exc)})
            raise
        ctx.emit("secrets_set", {"key": key})  # value intentionally excluded
        return {"key": key, "stored": True}

    @capability(
        id="chp.adapters.secrets.delete",
        version="1.0.0",
        description="Delete a secret by key.",
        category="security",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "minLength": 1},
            },
            "required": ["key"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["secrets"],
    )
    async def delete(self, ctx: Any, payload: dict) -> dict:
        key = payload["key"]
        try:
            deleted = self._backend.delete(key)
        except Exception as exc:
            ctx.emit("secrets_error", {"key": key, "reason": str(exc)})
            raise
        ctx.emit("secrets_delete", {"key": key, "deleted": deleted})
        return {"key": key, "deleted": deleted}

    @capability(
        id="chp.adapters.secrets.list",
        version="1.0.0",
        description="List available secret key names (no values returned).",
        category="security",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Optional prefix to filter key names.",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["secrets"],
    )
    async def list_secrets(self, ctx: Any, payload: dict) -> dict:
        prefix = payload.get("prefix", "")
        try:
            all_keys = self._backend.list_keys()
        except Exception as exc:
            ctx.emit("secrets_error", {"reason": str(exc)})
            raise
        keys = [k for k in all_keys if k.startswith(prefix)] if prefix else all_keys
        ctx.emit("secrets_list", {"count": len(keys), "keys": keys})
        return {"keys": keys, "count": len(keys)}
