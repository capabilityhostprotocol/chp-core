"""SecretsAdapter — runtime credential injection via CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Secret ``value`` — NEVER in evidence (any backend).
* ``set`` payload ``value`` — NEVER in evidence.
* Only key names, ``found``, ``deleted``, and counts are recorded.

Five capabilities: get, set, delete, list, bind. ``bind`` applies a secret to an
allowlisted sink (Vercel env, git credential) without ever returning the value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import sys

from chp_core import BaseAdapter, capability

from pathlib import Path

from .backends import EncryptedFileBackend, KeychainBackend, MemoryBackend

_EMITS = ["secrets_get", "secrets_set", "secrets_delete", "secrets_list", "secrets_bind", "secrets_error"]


# ---------------------------------------------------------------------------
# secrets.bind sinks — apply a secret to a side-effect WITHOUT returning the value.
# Each handler receives (value, spec) and returns a value-free target summary (for the
# result + evidence). Add a sink here; never a generic "run any command" sink.
# ---------------------------------------------------------------------------

def _sink_git_credential(value: str, spec: dict) -> dict:
    """Write an HTTPS git credential so later clones/fetches on `host` authenticate.

    Stores `https://<username>:<token>@<host>` in a git credential store file (0600),
    replacing any prior entry for the same host. Point git at it with
    `credential.helper 'store --file=<file>'` (default file is git's own ~/.git-credentials).
    """
    host = spec.get("host")
    if not host:
        raise ValueError("git_credential sink requires 'host'")
    username = spec.get("username") or "x-access-token"
    file = Path(spec.get("file") or (Path.home() / ".git-credentials")).expanduser()
    file.parent.mkdir(parents=True, exist_ok=True)
    kept = [
        line
        for line in (file.read_text().splitlines() if file.exists() else [])
        if line and f"@{host}" not in line
    ]
    kept.append(f"https://{username}:{value}@{host}")
    file.write_text("\n".join(kept) + "\n")
    try:
        file.chmod(0o600)
    except OSError:
        pass
    return {"type": "git_credential", "host": host, "file": str(file)}


def _sink_vercel_env(value: str, spec: dict) -> dict:
    """Set a Vercel project env var to the secret via the local (authed) `vercel` CLI.

    The value is fed on stdin — never in argv — so it never appears in a process list.
    Idempotent: removes any existing var first. `environments` defaults to all three;
    for a branch-scoped preview var pass `git_branch`.
    """
    import subprocess

    name = spec.get("name")
    if not name:
        raise ValueError("vercel_env sink requires 'name'")
    environments = spec.get("environments") or ["production", "preview", "development"]
    branch = spec.get("git_branch")
    cwd = spec.get("project_dir")
    applied = []
    for env in environments:
        scope = [env] + ([branch] if env == "preview" and branch else [])
        subprocess.run(["vercel", "env", "rm", name, *scope, "-y"],
                       capture_output=True, text=True, cwd=cwd)
        proc = subprocess.run(["vercel", "env", "add", name, *scope],
                              input=value, capture_output=True, text=True, cwd=cwd)
        applied.append(env if proc.returncode == 0 else f"{env}:FAILED")
    return {"type": "vercel_env", "name": name, "environments": applied}


_SINKS = {
    "git_credential": _sink_git_credential,
    "vercel_env": _sink_vercel_env,
}


def _default_backend() -> Any:
    """Durable-by-default backend, per platform — credentials MUST survive a host restart
    (MemoryBackend, the old default, lost them all every restart; now frequent with the
    self-healing agent). macOS → Keychain; Windows/Linux → an encrypted file
    (``~/.chp/secrets.enc`` + 0600 key). Any failure falls back to MemoryBackend rather than
    breaking construction — the node still runs, secrets are just ephemeral until fixed.
    """
    if sys.platform == "darwin":
        try:
            return KeychainBackend()
        except Exception:
            return MemoryBackend()
    try:
        return EncryptedFileBackend(Path.home() / ".chp" / "secrets.enc")
    except Exception:
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
        # The result carries the secret VALUE; keep it OUT of the §13 replay cache
        # (invocation_results) so no credential is ever at rest there. A credential
        # read re-executes anyway (freshness/revocation). (rad:3d5b718)
        metadata={"cache_results": False},
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

    @capability(
        id="chp.adapters.secrets.bind",
        version="1.0.0",
        description=(
            "Apply a secret to an allowlisted sink (set a Vercel env var, write a git "
            "credential). The value is used to perform the side-effect and is NEVER returned "
            "to the caller or written to evidence — for agentic use where the value must not "
            "enter the caller's context."
        ),
        category="security",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "minLength": 1},
                "sink": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["git_credential", "vercel_env"]},
                        # git_credential
                        "host": {"type": "string"},
                        "username": {"type": "string"},
                        "file": {"type": "string"},
                        # vercel_env
                        "name": {"type": "string"},
                        "environments": {"type": "array", "items": {"type": "string"}},
                        "git_branch": {"type": "string"},
                        "project_dir": {"type": "string"},
                    },
                    "required": ["type"],
                    "additionalProperties": False,
                },
            },
            "required": ["key", "sink"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["secrets"],
        # Side-effect with a live credential; never cache (freshness) and never at rest.
        metadata={"cache_results": False},
    )
    async def bind(self, ctx: Any, payload: dict) -> dict:
        key = payload["key"]
        sink = payload["sink"]
        sink_type = sink.get("type")
        handler = _SINKS.get(sink_type)
        if handler is None:
            ctx.emit("secrets_error", {"key": key, "reason": f"unknown sink {sink_type!r}"})
            raise ValueError(f"unknown sink type {sink_type!r}")
        try:
            value = self._backend.get(key)
        except Exception as exc:
            ctx.emit("secrets_error", {"key": key, "reason": str(exc)})
            raise
        if value is None:
            ctx.emit("secrets_get", {"key": key, "found": False})
            raise KeyError(f"Secret {key!r} not found")
        try:
            target = handler(value, sink)
        except Exception as exc:
            ctx.emit("secrets_error", {"key": key, "reason": str(exc)})
            raise
        # value intentionally excluded — only the key + value-free target summary
        ctx.emit("secrets_bind", {"key": key, "sink": sink_type, "target": target})
        return {"key": key, "sink": sink_type, "target": target, "applied": True}
