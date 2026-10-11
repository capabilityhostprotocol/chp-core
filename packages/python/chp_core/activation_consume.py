"""Host-side single-use consume store for activation grants (M1.3 wiring, ADR-002).

The PURE activation gate (``activation_gate.authorize_activation_effect``) can only check an
``approval_id`` against a *provided* consumed set — it cannot prevent a concurrent double-spend,
because two racing calls both observe ``approval_id ∉ consumed``. This store performs the
HOST-side ATOMIC check-and-consume: the first caller to consume an ``approval_id`` wins; any
concurrent or subsequent attempt loses. Atomicity is the database's (a UNIQUE primary key +
a single INSERT), not the process's, so it holds across threads and processes.

Wiring order at the pipeline (see host._prepare): run the gate FIRST (it may deny for many
reasons without ever touching the store), and only if it AUTHORIZES call ``consume`` — a False
return means another attempt already consumed this grant, so the effect is denied as a replay /
concurrent duplicate (NEG-ACT-005 / NEG-ACT-013).
"""
from __future__ import annotations

import sqlite3
import threading

from .types import utc_now


class ActivationConsumeStore:
    """Durable, atomic single-use ledger for activation ``approval_id``s."""

    def __init__(self, path: str = ":memory:") -> None:
        # A single connection shared across threads (check_same_thread=False) MUST be serialized —
        # concurrent use of one sqlite3.Connection otherwise raises. The lock makes every access on
        # this instance thread-safe (within-process atomicity); the UNIQUE primary key additionally
        # gives cross-CONNECTION / cross-process atomicity for a file-backed path. ``:memory:`` is
        # single-process only — a multi-process host MUST set a shared file path.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS consumed_activations ("
            "  approval_id TEXT PRIMARY KEY,"
            "  consumed_at TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def is_consumed(self, approval_id: str) -> bool:
        """Non-atomic read (for the gate's membership check / diagnostics)."""
        if not approval_id:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM consumed_activations WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return row is not None

    def consumed_ids(self) -> set[str]:
        """The full consumed set — passed to the pure gate as ``consumed_approval_ids``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT approval_id FROM consumed_activations").fetchall()
        return {r[0] for r in rows}

    def consume(self, approval_id: str) -> bool:
        """ATOMIC check-and-consume. Returns True iff THIS call consumed ``approval_id`` (the
        single winner); False if it was already consumed (replay / lost race) or the id is empty.
        Serialized by the instance lock (shared-connection safety) and backed by the UNIQUE primary
        key (cross-connection safety) — a duplicate INSERT raises IntegrityError → False."""
        if not approval_id or not isinstance(approval_id, str):
            return False
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO consumed_activations (approval_id, consumed_at) VALUES (?, ?)",
                        (approval_id, utc_now()),
                    )
                return True
            except sqlite3.IntegrityError:
                return False

    def close(self) -> None:
        with self._lock:
            self._conn.close()
