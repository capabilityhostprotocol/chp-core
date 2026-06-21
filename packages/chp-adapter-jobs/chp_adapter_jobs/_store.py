"""SQLite-backed job registry — durable across host restarts.

Mirrors the evidence store's threading model (one connection,
check_same_thread=False + a Lock, WAL). Job rows survive process restart; on
startup, jobs left in a non-terminal state (their executor didn't survive) are
reconciled to 'interrupted' so pollers get a definitive answer instead of
hanging forever.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_TERMINAL = ("completed", "failed", "interrupted")


class JobStore:
    def __init__(self, path: str = "") -> None:
        self.path = path or str(Path.home() / ".chp" / "jobs.sqlite")
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  job_id TEXT PRIMARY KEY,
                  capability_id TEXT NOT NULL,
                  status TEXT NOT NULL,
                  submitted_at REAL NOT NULL,
                  started_at REAL,
                  completed_at REAL,
                  success INTEGER,
                  result_json TEXT,
                  error TEXT
                )
                """
            )
            self._conn.commit()

    def reconcile_interrupted(self) -> int:
        """Mark non-terminal jobs (from a prior, now-dead process) as interrupted."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE jobs SET status='interrupted', completed_at=?, "
                "error='host restarted before completion' "
                "WHERE status IN ('submitted','running')",
                (time.time(),),
            )
            self._conn.commit()
            return cur.rowcount

    def create(self, job_id: str, capability_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs(job_id, capability_id, status, submitted_at) "
                "VALUES (?, ?, 'submitted', ?)",
                (job_id, capability_id, time.time()),
            )
            self._conn.commit()

    def mark_running(self, job_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status='running', started_at=? WHERE job_id=?",
                (time.time(), job_id),
            )
            self._conn.commit()

    def mark_done(self, job_id: str, success: bool, result: Any, error: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status=?, success=?, result_json=?, error=?, completed_at=? "
                "WHERE job_id=?",
                (
                    "completed" if success else "failed",
                    1 if success else 0,
                    json.dumps(result, default=str) if success else None,
                    error,
                    time.time(),
                    job_id,
                ),
            )
            self._conn.commit()

    def _row_summary(self, row: sqlite3.Row) -> dict:
        duration_ms = None
        if row["started_at"] is not None and row["completed_at"] is not None:
            duration_ms = round((row["completed_at"] - row["started_at"]) * 1000)
        success = None if row["success"] is None else bool(row["success"])
        return {
            "job_id": row["job_id"],
            "capability_id": row["capability_id"],
            "status": row["status"],
            "success": success,
            "error": row["error"],
            "duration_ms": duration_ms,
        }

    def get_summary(self, job_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._row_summary(row) if row else None

    def get_result(self, job_id: str) -> dict | None:
        """Return {status, success, result, error} or None if unknown."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        result = json.loads(row["result_json"]) if row["result_json"] else None
        success = None if row["success"] is None else bool(row["success"])
        return {"status": row["status"], "success": success, "result": result, "error": row["error"]}

    def list_summaries(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM jobs ORDER BY submitted_at DESC").fetchall()
        return [self._row_summary(r) for r in rows]
