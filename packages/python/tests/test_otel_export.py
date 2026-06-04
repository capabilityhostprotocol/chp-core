"""Tests for v0.2.8 OTel export: export_otlp_http, health endpoint, CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import unittest.mock
from pathlib import Path

import pytest

from chp_core.otel import export_otlp_http, replay_to_otel_spans
from chp_core.session import AgentSession
from chp_core.store import SQLiteEvidenceStore

_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


# ---------------------------------------------------------------------------
# replay_to_otel_spans
# ---------------------------------------------------------------------------

def test_replay_to_otel_spans_groups_by_invocation(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "otel-group-test"
    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})
        session.record_tool("Read", {"file_path": "/x"}, {"content": "hi"})

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()

    spans = replay_to_otel_spans(events)
    # Each tool_use event has a unique invocation_id → one span per tool call
    assert len(spans) >= 2
    span_ids = {s["span_id"] for s in spans}
    assert len(span_ids) == len(spans)


def test_replay_to_otel_spans_has_required_fields(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="otel-fields") as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("otel-fields")
    store.close()

    spans = replay_to_otel_spans(events)
    for span in spans:
        assert "name" in span
        assert "span_id" in span
        assert "attributes" in span


# ---------------------------------------------------------------------------
# export_otlp_http (mocked)
# ---------------------------------------------------------------------------

def test_export_otlp_http_posts_to_endpoint(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    with AgentSession(store_path=store_path, session_id="otel-export") as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation("otel-export")
    store.close()
    spans = replay_to_otel_spans(events)

    mock_resp = unittest.mock.MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)

    with unittest.mock.patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        result = export_otlp_http(spans, endpoint="http://fake-collector:4318/v1/traces")

    assert result["exported"] == len(spans)
    assert result["status"] == 200
    assert result["endpoint"] == "http://fake-collector:4318/v1/traces"
    mock_urlopen.assert_called_once()


# ---------------------------------------------------------------------------
# CLI: chp session otel --dry-run
# ---------------------------------------------------------------------------

def _run_cli(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "chp_core.cli"] + cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _PACKAGES_DIR},
    )


def test_session_otel_cli_dry_run_exits_0(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    session_id = "otel-cli-test"
    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "echo hi"}, {"output": "hi", "exit_code": 0})

    result = _run_cli(["session", "otel", session_id, "--store", store_path, "--dry-run"])
    assert result.returncode == 0
    spans = json.loads(result.stdout)
    assert isinstance(spans, list)
    assert len(spans) > 0


def test_session_otel_cli_empty_session_exits_1(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    # Create store but don't add any events
    store = SQLiteEvidenceStore(store_path)
    store.close()

    result = _run_cli(["session", "otel", "nonexistent-session", "--store", store_path, "--dry-run"])
    assert result.returncode == 1


# ---------------------------------------------------------------------------
# HTTP /health endpoint
# ---------------------------------------------------------------------------

def test_health_endpoint_has_capability_count() -> None:
    from chp_core import LocalCapabilityHost
    from chp_core.http import create_http_server

    host = LocalCapabilityHost("test-host")
    server = create_http_server(host, port=0)
    port = server.server_address[1]

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    import urllib.request
    url = f"http://127.0.0.1:{port}/health"
    with urllib.request.urlopen(url, timeout=2) as resp:
        data = json.loads(resp.read())

    assert data["status"] == "ok"
    assert "capability_count" in data
    assert "host_id" in data
