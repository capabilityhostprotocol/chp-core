"""Append-only local evidence store for CHP v0.1."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .types import ConversationEvent, ExecutionEvidence, JSON


@dataclass
class ChainVerificationResult:
    """Result of verifying the SHA256 hash chain for a correlation ID."""
    correlation_id: str
    event_count: int
    verified_count: int      # events with stored content_hash
    unverified_count: int    # legacy events without hash (NULL)
    valid: bool
    first_broken_sequence: int | None


def _compute_event_hash(event_dict: JSON, prev_hash: str | None) -> str:
    """SHA256 of stable event fields + prev_hash link."""
    correlation = event_dict.get("correlation") or {}
    stable: JSON = {
        "event_id": event_dict.get("event_id"),
        "event_type": event_dict.get("event_type"),
        "invocation_id": event_dict.get("invocation_id"),
        "capability_id": event_dict.get("capability_id"),
        "host_id": event_dict.get("host_id"),
        "correlation_id": correlation.get("correlation_id") if isinstance(correlation, dict) else None,
        "timestamp": event_dict.get("timestamp"),
        "outcome": event_dict.get("outcome"),
        "payload": event_dict.get("payload"),
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


class SQLiteEvidenceStore:
    """SQLite-backed evidence store.

    The store uses insert-only writes. Existing events are never updated or
    replaced. v0.2.6+ adds SHA256 hash chaining: each event stores its own
    content_hash and the prev_hash of the preceding event in the same
    correlation. Use verify_chain() to detect tampering.
    """

    def __init__(self, path: str | Path = ".chp/evidence.sqlite") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Durability + read/write concurrency: WAL lets readers (replay/query)
        # proceed without blocking the append writer, and avoids ROLLBACK-journal
        # corruption on unclean shutdown. synchronous=NORMAL is the standard WAL
        # pairing. (:memory: ignores journal pragmas.) Same pattern as memory.py.
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
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
            # Add hash columns to existing stores (graceful migration)
            for ddl in (
                "ALTER TABLE evidence_events ADD COLUMN content_hash TEXT",
                "ALTER TABLE evidence_events ADD COLUMN prev_hash TEXT",
            ):
                try:
                    self._conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass  # column already exists
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
                "CREATE INDEX IF NOT EXISTS idx_evidence_outcome "
                "ON evidence_events(outcome, sequence)"
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO evidence_sequence(sequence)
                SELECT sequence FROM evidence_events
                """
            )
            self._conn.commit()

    def append(self, event: ExecutionEvidence | ConversationEvent) -> ExecutionEvidence | ConversationEvent:
        if isinstance(event, ConversationEvent):
            return self._append_conversation(event)
        return self._append_evidence(event)

    def _insert_evidence_locked(self, event: ExecutionEvidence) -> None:
        """Insert one evidence event. Caller MUST hold self._lock; does not commit.

        Reads prev_hash from rows inserted earlier in the same (uncommitted)
        transaction too, so hash-chaining is correct within a batch.
        """
        cursor = self._conn.execute("INSERT INTO evidence_sequence DEFAULT VALUES")
        event.sequence = int(cursor.lastrowid or 0)
        data = event.to_dict()
        prev_row = self._conn.execute(
            "SELECT content_hash FROM evidence_events "
            "WHERE correlation_id = ? ORDER BY sequence DESC LIMIT 1",
            (event.correlation.correlation_id,),
        ).fetchone()
        prev_hash: str | None = prev_row["content_hash"] if prev_row else None
        content_hash = _compute_event_hash(data, prev_hash)

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
              event_json,
              content_hash,
              prev_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                content_hash,
                prev_hash,
            ),
        )

    def _append_evidence(self, event: ExecutionEvidence) -> ExecutionEvidence:
        with self._lock:
            try:
                self._insert_evidence_locked(event)
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(f"failed to append evidence event: {event.event_id}") from exc
            self._conn.commit()
        return event

    def _append_conversation(self, event: ConversationEvent) -> ConversationEvent:
        payload_dict: JSON = {
            "role": event.role,
            "agent": event.agent,
            "word_count": event.word_count,
            "content_hash": event.content_hash,
        }
        if event.content is not None:
            payload_dict["content"] = event.content
        with self._lock:
            try:
                self._insert_conversation_locked(event, payload_dict)
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(f"failed to append conversation event: {event.event_id}") from exc
            self._conn.commit()
        return event

    def _insert_conversation_locked(self, event: ConversationEvent, payload_dict: JSON | None = None) -> None:
        """Insert one conversation event. Caller MUST hold self._lock; does not commit."""
        if payload_dict is None:
            payload_dict = {
                "role": event.role,
                "agent": event.agent,
                "word_count": event.word_count,
                "content_hash": event.content_hash,
            }
            if event.content is not None:
                payload_dict["content"] = event.content
        cursor = self._conn.execute("INSERT INTO evidence_sequence DEFAULT VALUES")
        event.sequence = int(cursor.lastrowid or 0)
        data = event.to_dict()
        prev_row = self._conn.execute(
            "SELECT content_hash FROM evidence_events "
            "WHERE correlation_id = ? ORDER BY sequence DESC LIMIT 1",
            (event.correlation.correlation_id,),
        ).fetchone()
        prev_hash: str | None = prev_row["content_hash"] if prev_row else None
        chain_hash = _compute_event_hash(data, prev_hash)

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
              event_json,
              content_hash,
              prev_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.sequence,
                event.event_id,
                "conversation_turn",
                event.event_id,          # invocation_id = own event_id
                "chp.core.conversation.turn",
                None,                    # capability_version
                "",                      # host_id (not tied to one host)
                event.correlation.correlation_id,
                event.timestamp,
                None,                    # outcome
                json.dumps(payload_dict, sort_keys=True),
                json.dumps(data, sort_keys=True),
                chain_hash,
                prev_hash,
            ),
        )

    def append_many(self, events: Iterable[ExecutionEvidence]) -> list[ExecutionEvidence]:
        """Append a batch of events in a single transaction (one commit).

        Hash-chaining stays correct: events are inserted in order on one
        connection, so each event's prev_hash lookup sees the prior batch rows.
        Conversation events (if any) are routed through their own insert path.
        """
        batch = list(events)
        if not batch:
            return []
        with self._lock:
            try:
                for event in batch:
                    if isinstance(event, ConversationEvent):
                        self._insert_conversation_locked(event)
                    else:
                        self._insert_evidence_locked(event)
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError("failed to append evidence batch") from exc
            self._conn.commit()
        return batch

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

    def query(
        self,
        *,
        capability_id: str | None = None,
        outcome: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int | None = None,
    ) -> list[JSON]:
        clauses: list[str] = []
        params: list[str | int] = []
        if capability_id is not None:
            clauses.append("capability_id = ?")
            params.append(capability_id)
        if outcome is not None:
            clauses.append("outcome = ?")
            params.append(outcome)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_clause = f"LIMIT {int(limit)}" if limit is not None else ""
        sql = f"SELECT sequence, event_json FROM evidence_events {where} ORDER BY sequence ASC {limit_clause}".strip()

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_event(row) for row in rows]

    def by_correlation_with_hashes(self, correlation_id: str) -> list[JSON]:
        """Like by_correlation but includes content_hash and prev_hash in each dict."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT sequence, event_json, content_hash, prev_hash
                FROM evidence_events
                WHERE correlation_id = ?
                ORDER BY sequence ASC
                """,
                (correlation_id,),
            ).fetchall()
        result = []
        for row in rows:
            data = json.loads(row["event_json"])
            data["sequence"] = int(row["sequence"])
            if row["content_hash"] is not None:
                data["content_hash"] = row["content_hash"]
            if row["prev_hash"] is not None:
                data["prev_hash"] = row["prev_hash"]
            result.append(data)
        return result

    def children_of(self, session_id: str) -> list[str]:
        """Return child session IDs spawned by the given session (via session_spawn events)."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT event_json
                FROM evidence_events
                WHERE correlation_id = ? AND event_type = 'session_spawn'
                ORDER BY sequence ASC
                """,
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            try:
                event = json.loads(row["event_json"])
                child_id = event.get("payload", {}).get("child_session_id")
                if child_id and isinstance(child_id, str):
                    result.append(child_id)
            except (json.JSONDecodeError, AttributeError):
                pass
        return result

    def verify_chain(self, correlation_id: str) -> ChainVerificationResult:
        """Walk stored events in sequence order and verify the SHA256 hash chain.

        Events without a stored hash (legacy, written before v0.2.6) are counted
        separately and do not break the chain.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT sequence, event_json, content_hash, prev_hash
                FROM evidence_events
                WHERE correlation_id = ?
                ORDER BY sequence ASC
                """,
                (correlation_id,),
            ).fetchall()

        verified_count = 0
        unverified_count = 0
        expected_prev: str | None = None
        first_broken: int | None = None

        for row in rows:
            stored_hash: str | None = row["content_hash"]
            stored_prev: str | None = row["prev_hash"]

            if stored_hash is None:
                unverified_count += 1
                # Don't advance expected_prev — legacy events break the chain tracking
                continue

            # Re-compute hash from stored event_json
            try:
                event_dict = json.loads(row["event_json"])
            except json.JSONDecodeError:
                if first_broken is None:
                    first_broken = int(row["sequence"])
                continue

            recomputed = _compute_event_hash(event_dict, stored_prev)
            if recomputed != stored_hash or stored_prev != expected_prev:
                if first_broken is None:
                    first_broken = int(row["sequence"])
            else:
                verified_count += 1

            expected_prev = stored_hash

        return ChainVerificationResult(
            correlation_id=correlation_id,
            event_count=len(rows),
            verified_count=verified_count,
            unverified_count=unverified_count,
            valid=first_broken is None,
            first_broken_sequence=first_broken,
        )

    def count_by_correlation(self, correlation_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS count FROM evidence_events WHERE correlation_id = ?",
                (correlation_id,),
            ).fetchone()
        return int(row["count"])

    def count_by_correlation_event_type(self, correlation_id: str, event_type: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS count FROM evidence_events "
                "WHERE correlation_id = ? AND event_type = ?",
                (correlation_id, event_type),
            ).fetchone()
        return int(row["count"])

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
