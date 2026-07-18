"""Upgrade / rollback discipline for the durable evidence store (v1.0-gate hardening).

The evidence ledger outlives any single chp-core build, so opening it across versions must
be disciplined: a FORWARD upgrade (older schema → this build) migrates in place without losing
evidence; a ROLLBACK (a store written by a NEWER build) must FAIL CLOSED rather than silently
downgrade a store whose newer columns/semantics this build does not understand.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

_V = SQLiteEvidenceStore._SCHEMA_VERSION


def _make_legacy_store(path: str) -> None:
    """A pre-v0.2.6 store: evidence_events WITHOUT the hash columns, user_version=1, and
    none of the tables the migration later adds (evidence_sequence/correlation_heads/…)."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE evidence_events ("
        "  sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, event_type TEXT NOT NULL,"
        "  invocation_id TEXT NOT NULL, capability_id TEXT NOT NULL, capability_version TEXT,"
        "  host_id TEXT NOT NULL, correlation_id TEXT NOT NULL, timestamp TEXT NOT NULL,"
        "  outcome TEXT, payload_json TEXT NOT NULL, event_json TEXT NOT NULL)")
    ev = {"event_id": "e1", "event_type": "execution_started", "invocation_id": "inv1",
          "capability_id": "demo.echo", "host_id": "old-host",
          "correlation": {"correlation_id": "legacy-1"}, "timestamp": "2026-01-01T00:00:00Z",
          "outcome": None, "payload": {"v": 1}}
    conn.execute(
        "INSERT INTO evidence_events (sequence, event_id, event_type, invocation_id, "
        "capability_id, host_id, correlation_id, timestamp, payload_json, event_json) "
        "VALUES (1,?,?,?,?,?,?,?,?,?)",
        ("e1", "execution_started", "inv1", "demo.echo", "old-host", "legacy-1",
         "2026-01-01T00:00:00Z", json.dumps({"v": 1}), json.dumps(ev)))
    conn.execute("PRAGMA user_version=1")
    conn.commit()
    conn.close()


def test_forward_migration_preserves_legacy_evidence(tmp_path) -> None:
    p = str(tmp_path / "legacy.sqlite")
    _make_legacy_store(p)
    store = SQLiteEvidenceStore(p)  # opening triggers the migration
    try:
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == _V  # stamped current
        evs = store.by_correlation("legacy-1")
        assert len(evs) == 1 and evs[0]["event_id"] == "e1"  # no evidence lost
        cols = {r[1] for r in store._conn.execute("PRAGMA table_info(evidence_events)")}
        assert "content_hash" in cols and "prev_hash" in cols  # hash columns added
    finally:
        store.close()


def test_migrated_store_accepts_new_hashed_evidence(tmp_path) -> None:
    p = str(tmp_path / "legacy2.sqlite")
    _make_legacy_store(p)
    store = SQLiteEvidenceStore(p)
    host = LocalCapabilityHost("new-host", store=store)

    async def echo(_ctx, _payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="demo.echo", version="1.0.0", description="."), echo)
    asyncio.run(host.ainvoke("demo.echo", {}, correlation={"correlation_id": "fresh-1"}))
    # a wholly post-migration correlation is fully hash-chained and verifies strictly
    assert store.verify_chain("fresh-1", strict=True).valid
    store.close()


def test_rollback_newer_schema_fails_closed(tmp_path) -> None:
    p = str(tmp_path / "future.sqlite")
    store = SQLiteEvidenceStore(p)  # current schema
    store._conn.execute(f"PRAGMA user_version={_V + 1}")  # pretend a newer build wrote it
    store._conn.commit()
    store.close()

    with pytest.raises(RuntimeError, match="newer than this chp-core"):
        SQLiteEvidenceStore(p)

    # the refused store was NOT silently downgraded — a future build can still open it
    conn = sqlite3.connect(p)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == _V + 1
    finally:
        conn.close()


def test_reopen_current_store_is_idempotent(tmp_path) -> None:
    p = str(tmp_path / "cur.sqlite")
    SQLiteEvidenceStore(p).close()
    s = SQLiteEvidenceStore(p)  # fast path: user_version already current, no error, no re-DDL
    try:
        assert s._conn.execute("PRAGMA user_version").fetchone()[0] == _V
    finally:
        s.close()


def test_default_store_path_env_override(tmp_path, monkeypatch) -> None:
    # The store-less-host footgun: a default store is CWD-relative + shared. CHP_EVIDENCE_PATH
    # lets an embedder redirect that default globally without touching call sites.
    monkeypatch.chdir(tmp_path)  # contain the CWD-relative default's side effects
    target = str(tmp_path / "redirected.sqlite")
    monkeypatch.setenv("CHP_EVIDENCE_PATH", target)
    s = SQLiteEvidenceStore()  # no path → env override
    try:
        assert s.path == target
    finally:
        s.close()
    # env unset → the historical CWD-relative default (backward compatible)
    monkeypatch.delenv("CHP_EVIDENCE_PATH", raising=False)
    s2 = SQLiteEvidenceStore()
    try:
        assert s2.path == ".chp/evidence.sqlite"
    finally:
        s2.close()
    # an explicit path always wins over both
    s3 = SQLiteEvidenceStore(str(tmp_path / "explicit.sqlite"))
    try:
        assert s3.path.endswith("explicit.sqlite")
    finally:
        s3.close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider"]))
