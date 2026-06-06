"""MemoryCapability — persistent, scoped key-value memory for CHP agents.

Memory is stored in a separate SQLite file from the evidence store so the
evidence store stays append-only while memory entries remain mutable.

Usage (standalone)::

    mem = MemoryCapability(".chp/memory.sqlite")
    mem.set("last_task", "write tests", scope="project", scope_id="chp-agent")
    value = mem.get("last_task", scope="project", scope_id="chp-agent")
    mem.close()

Usage (as a CHP capability on a host)::

    host = LocalCapabilityHost("my-host", store=store)
    mem = MemoryCapability(".chp/memory.sqlite")
    register_memory_capability(host, mem)
    # host.invoke("memory.set", {"key": "x", "value": 42, "scope": "session"})
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    JSON,
    MemoryScope,
    new_id,
    utc_now,
)

if TYPE_CHECKING:
    from .host import LocalCapabilityHost

_MEMORY_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
]


class MemoryCapability:
    """Persistent, scoped key-value memory backed by SQLite.

    Scopes:
    - ``session`` — tied to a single agent session ID
    - ``project`` — shared within a project directory
    - ``user``    — shared across all projects for a user (commercial encryption: future)
    """

    def __init__(self, store_path: str | Path = ".chp/memory.sqlite") -> None:
        self._path = Path(store_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id         TEXT PRIMARY KEY,
                key        TEXT NOT NULL,
                scope      TEXT NOT NULL,
                scope_id   TEXT NOT NULL DEFAULT '',
                value      TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(key, scope, scope_id)
            )
        """)
        self._conn.commit()

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, key: str, *, scope: MemoryScope = "session", scope_id: str = "") -> Any | None:
        """Return the stored value for *key* in the given scope, or ``None``."""
        row = self._conn.execute(
            "SELECT value FROM memory WHERE key=? AND scope=? AND scope_id=?",
            (key, scope, scope_id),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def set(self, key: str, value: Any, *, scope: MemoryScope = "session", scope_id: str = "") -> None:
        """Upsert *value* under *key* in the given scope."""
        now = utc_now()
        self._conn.execute(
            """INSERT INTO memory (id, key, scope, scope_id, value, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(key, scope, scope_id)
               DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (new_id("mem"), key, scope, scope_id, json.dumps(value), now, now),
        )
        self._conn.commit()

    def delete(self, key: str, *, scope: MemoryScope = "session", scope_id: str = "") -> bool:
        """Delete *key* from the given scope. Returns ``True`` if a row was removed."""
        cursor = self._conn.execute(
            "DELETE FROM memory WHERE key=? AND scope=? AND scope_id=?",
            (key, scope, scope_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list(self, *, scope: MemoryScope = "session", scope_id: str = "") -> list[str]:
        """Return all keys in the given scope, sorted alphabetically."""
        rows = self._conn.execute(
            "SELECT key FROM memory WHERE scope=? AND scope_id=? ORDER BY key",
            (scope, scope_id),
        ).fetchall()
        return [row[0] for row in rows]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ── Host registration ─────────────────────────────────────────────────────────


def register_memory_capability(host: "LocalCapabilityHost", memory: MemoryCapability) -> None:
    """Register memory.get / set / delete / list as CHP capabilities on *host*."""

    # ── memory.get ────────────────────────────────────────────────────────────
    async def _get(ctx: Any, payload: JSON) -> JSON:
        key = str(payload.get("key", ""))
        scope: MemoryScope = payload.get("scope", "session")
        scope_id: str = payload.get("scope_id", "")
        ctx.emit("execution_started", {"capability_id": "memory.get"}, redacted=False)
        try:
            value = memory.get(key, scope=scope, scope_id=scope_id)
            found = value is not None
            ctx.emit("memory_read", {"key": key, "scope": scope, "scope_id": scope_id, "found": found}, redacted=False)
            ctx.emit("execution_completed", {"outcome": "success"}, redacted=False)
            return {"value": value, "found": found}
        except Exception as exc:
            ctx.emit("execution_failed", {"reason": str(exc), "exception_type": type(exc).__name__}, redacted=False)
            raise

    # ── memory.set ────────────────────────────────────────────────────────────
    async def _set(ctx: Any, payload: JSON) -> JSON:
        key = str(payload.get("key", ""))
        value = payload.get("value")
        scope: MemoryScope = payload.get("scope", "session")
        scope_id: str = payload.get("scope_id", "")
        ctx.emit("execution_started", {"capability_id": "memory.set"}, redacted=False)
        try:
            memory.set(key, value, scope=scope, scope_id=scope_id)
            serialized_len = len(json.dumps(value).encode())
            ctx.emit("memory_written", {"key": key, "scope": scope, "scope_id": scope_id, "bytes_written": serialized_len}, redacted=False)
            ctx.emit("execution_completed", {"outcome": "success"}, redacted=False)
            return {"key": key, "scope": scope}
        except Exception as exc:
            ctx.emit("execution_failed", {"reason": str(exc), "exception_type": type(exc).__name__}, redacted=False)
            raise

    # ── memory.delete ─────────────────────────────────────────────────────────
    async def _delete(ctx: Any, payload: JSON) -> JSON:
        key = str(payload.get("key", ""))
        scope: MemoryScope = payload.get("scope", "session")
        scope_id: str = payload.get("scope_id", "")
        ctx.emit("execution_started", {"capability_id": "memory.delete"}, redacted=False)
        try:
            existed = memory.delete(key, scope=scope, scope_id=scope_id)
            ctx.emit("memory_deleted", {"key": key, "scope": scope, "scope_id": scope_id, "existed": existed}, redacted=False)
            ctx.emit("execution_completed", {"outcome": "success"}, redacted=False)
            return {"key": key, "existed": existed}
        except Exception as exc:
            ctx.emit("execution_failed", {"reason": str(exc), "exception_type": type(exc).__name__}, redacted=False)
            raise

    # ── memory.list ───────────────────────────────────────────────────────────
    async def _list(ctx: Any, payload: JSON) -> JSON:
        scope: MemoryScope = payload.get("scope", "session")
        scope_id: str = payload.get("scope_id", "")
        ctx.emit("execution_started", {"capability_id": "memory.list"}, redacted=False)
        try:
            keys = memory.list(scope=scope, scope_id=scope_id)
            ctx.emit("execution_completed", {"outcome": "success"}, redacted=False)
            return {"keys": keys, "count": len(keys)}
        except Exception as exc:
            ctx.emit("execution_failed", {"reason": str(exc), "exception_type": type(exc).__name__}, redacted=False)
            raise

    _memory_emits = _MEMORY_EMITS + ["memory_read"]
    _write_emits = _MEMORY_EMITS + ["memory_written"]
    _delete_emits = _MEMORY_EMITS + ["memory_deleted"]

    host.register(
        CapabilityDescriptor(
            id="memory.get",
            version="0.1.0",
            description="Read a value from scoped agent memory.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            tags=["memory", "cognition"],
            emits=_memory_emits,
        ),
        _get,
    )
    host.register(
        CapabilityDescriptor(
            id="memory.set",
            version="0.1.0",
            description="Write or update a value in scoped agent memory.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            tags=["memory", "cognition"],
            emits=_write_emits,
        ),
        _set,
    )
    host.register(
        CapabilityDescriptor(
            id="memory.delete",
            version="0.1.0",
            description="Delete a key from scoped agent memory.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            tags=["memory", "cognition"],
            emits=_delete_emits,
        ),
        _delete,
    )
    host.register(
        CapabilityDescriptor(
            id="memory.list",
            version="0.1.0",
            description="List all keys in a memory scope.",
            category=CapabilityCategory.AGENT_OPERATIONS,
            tags=["memory", "cognition"],
            emits=_MEMORY_EMITS,
        ),
        _list,
    )
