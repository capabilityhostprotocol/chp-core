"""Tests for v0.2.6 evidence integrity: SHA256 hash chaining and verify_chain."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from chp_core.session import AgentSession
from chp_core.store import SQLiteEvidenceStore, _compute_event_hash

_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


# ---------------------------------------------------------------------------
# Hash storage
# ---------------------------------------------------------------------------

def test_append_sets_content_hash(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="hash-test") as session:
        session.record_tool("Bash", {"command": "echo hi"}, {"output": "hi", "exit_code": 0})

    store = SQLiteEvidenceStore(store_path)
    conn = store._conn
    rows = conn.execute(
        "SELECT content_hash FROM evidence_events WHERE correlation_id = 'hash-test'"
    ).fetchall()
    store.close()

    hashes = [r["content_hash"] for r in rows]
    assert all(h is not None and len(h) == 64 for h in hashes), f"Bad hashes: {hashes}"


def test_append_links_prev_hash(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="chain-test") as session:
        session.record_tool("Bash", {"command": "first"}, {"output": "1"})
        session.record_tool("Bash", {"command": "second"}, {"output": "2"})

    store = SQLiteEvidenceStore(store_path)
    conn = store._conn
    rows = conn.execute(
        "SELECT sequence, content_hash, prev_hash FROM evidence_events "
        "WHERE correlation_id = 'chain-test' ORDER BY sequence ASC"
    ).fetchall()
    store.close()

    # First event has no prev_hash; each subsequent event's prev_hash == previous event's content_hash
    assert rows[0]["prev_hash"] is None
    for i in range(1, len(rows)):
        assert rows[i]["prev_hash"] == rows[i - 1]["content_hash"], (
            f"Chain broken at sequence {rows[i]['sequence']}"
        )


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------

def test_verify_chain_valid(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="verify-ok") as session:
        session.record_tool("Read", {"file_path": "/tmp/f"}, {"content": "hi"})
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})

    store = SQLiteEvidenceStore(store_path)
    result = store.verify_chain("verify-ok")
    store.close()

    assert result.valid is True
    assert result.first_broken_sequence is None
    assert result.event_count >= 2
    assert result.verified_count >= 2


def test_verify_chain_detects_tampering(tmp_path) -> None:
    import sqlite3

    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="tamper-test") as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})
        session.record_tool("Read", {"file_path": "/x"}, {"content": "abc"})

    # Directly mutate the event_json of the second tool event (not session_completed)
    conn = sqlite3.connect(store_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT sequence, event_json FROM evidence_events "
        "WHERE correlation_id = 'tamper-test' ORDER BY sequence ASC"
    ).fetchall()
    # Mutate the first event's payload
    first_seq = rows[0]["sequence"]
    bad_json = json.dumps({"tampered": True})
    conn.execute(
        "UPDATE evidence_events SET event_json = ? WHERE sequence = ?",
        (bad_json, first_seq),
    )
    conn.commit()
    conn.close()

    store = SQLiteEvidenceStore(store_path)
    result = store.verify_chain("tamper-test")
    store.close()

    assert result.valid is False
    assert result.first_broken_sequence is not None


def test_verify_chain_handles_legacy_no_hash_events(tmp_path) -> None:
    import sqlite3

    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="legacy-test") as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})

    # Null out the hashes to simulate a pre-v0.2.6 event
    conn = sqlite3.connect(store_path)
    conn.execute(
        "UPDATE evidence_events SET content_hash = NULL, prev_hash = NULL "
        "WHERE correlation_id = 'legacy-test'"
    )
    conn.commit()
    conn.close()

    store = SQLiteEvidenceStore(store_path)
    result = store.verify_chain("legacy-test")
    store.close()

    # Legacy events are counted as unverified, chain is not marked broken
    assert result.valid is True
    assert result.unverified_count > 0
    assert result.verified_count == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_cli(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "chp_core.cli"] + cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _PACKAGES_DIR},
    )


def test_cli_verify_evidence_exits_0_on_valid(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="cli-verify") as session:
        session.record_tool("Bash", {"command": "echo hi"}, {"output": "hi", "exit_code": 0})

    result = _run_cli(["verify-evidence", "cli-verify", "--store", store_path])
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["valid"] is True


def test_cli_session_export_includes_hashes(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="export-hash") as session:
        session.record_tool("Read", {"file_path": "/x"}, {"content": "hi"})

    result = _run_cli(["session", "export", "export-hash", "--store", store_path])
    assert result.returncode == 0
    bundle = json.loads(result.stdout)
    assert bundle["hashes_included"] is True
    assert bundle["chain_valid"] is True
