"""Append-only local evidence store for CHP v0.1."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterable

from .types import ExecutionEvidence, JSON


class SQLiteEvidenceStore:
    """SQLite-backed evidence store.

    The store uses insert-only writes. Existing events are never updated or
    replaced. This is an integrity baseline, not a tamper-proof ledger.
    """

    def __init__(self, path: str | Path = ".chp/evidence.sqlite") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_sequence (
                  sequence INTEGER PRIMARY KEY AUTOINCREMENT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_events (
                  sequence INTEGER PRIMARY KEY,
                  event_id TEXT UNIQUE NOT NULL,
                  event_type TEXT NOT NULL,
                  invocation_id TEXT NOT NULL,
                  capability_id TEXT NOT NULL,
                  capability_version TEXT,
                  host_id TEXT NOT NULL,
                  correlation_id TEXT NOT NULL,
                  timestamp TEXT NOT NULL,
                  outcome TEXT,
                  payload_json TEXT NOT NULL,
                  event_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_correlation "
                "ON evidence_events(correlation_id, sequence)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_invocation "
                "ON evidence_events(invocation_id, sequence)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_capability "
                "ON evidence_events(capability_id, sequence)"
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO evidence_sequence(sequence)
                SELECT sequence FROM evidence_events
                """
            )
            self._conn.commit()

    def append(self, event: ExecutionEvidence) -> ExecutionEvidence:
        with self._lock:
            try:
                cursor = self._conn.execute("INSERT INTO evidence_sequence DEFAULT VALUES")
                event.sequence = int(cursor.lastrowid)
                data = event.to_dict()
                self._conn.execute(
                    """
                    INSERT INTO evidence_events (
                      sequence,
                      event_id,
                      event_type,
                      invocation_id,
                      capability_id,
                      capability_version,
                      host_id,
                      correlation_id,
                      timestamp,
                      outcome,
                      payload_json,
                      event_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.sequence,
                        event.event_id,
                        event.event_type,
                        event.invocation_id,
                        event.capability_id,
                        event.capability_version,
                        event.host_id,
                        event.correlation.correlation_id,
                        event.timestamp,
                        event.outcome,
                        json.dumps(event.payload, sort_keys=True),
                        json.dumps(data, sort_keys=True),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(f"failed to append evidence event: {event.event_id}") from exc
            self._conn.commit()
        return event

    def append_many(self, events: Iterable[ExecutionEvidence]) -> list[ExecutionEvidence]:
        return [self.append(event) for event in events]

    def by_correlation(self, correlation_id: str) -> list[JSON]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT sequence, event_json
                FROM evidence_events
                WHERE correlation_id = ?
                ORDER BY sequence ASC
                """,
                (correlation_id,),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def by_invocation(self, invocation_id: str) -> list[JSON]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT sequence, event_json
                FROM evidence_events
                WHERE invocation_id = ?
                ORDER BY sequence ASC
                """,
                (invocation_id,),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def all(self) -> list[JSON]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT sequence, event_json FROM evidence_events ORDER BY sequence ASC"
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> JSON:
        data = json.loads(row["event_json"])
        data["sequence"] = int(row["sequence"])
        return data

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS count FROM evidence_events").fetchone()
        return int(row["count"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
