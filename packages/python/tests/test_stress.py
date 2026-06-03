"""Stress and performance tests for CHP v0.2+ — marked slow/perf.

Run explicitly with:
    pytest -m "slow or perf" -v tests/test_stress.py

These tests are excluded from the fast CI path (-m "not slow") but run in
the staging pipeline before every production release.
"""

from __future__ import annotations

import statistics
import tempfile
import threading
import time

import pytest

from chp_core.hooks import process_post_tool_use, process_pre_tool_use
from chp_core.policy import BlockPattern, PolicyConfig, evaluate_policy
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _post_payload(session_id: str = "stress-session", cmd: str = "echo hi") -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "tool_response": {"output": "hi", "exit_code": 0},
        "cwd": "/tmp",
    }


def _pre_payload(session_id: str = "stress-session", cmd: str = "echo hi") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "cwd": "/tmp",
    }


# ---------------------------------------------------------------------------
# Concurrent write safety
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_concurrent_hook_writes_no_corruption(tmp_path) -> None:
    """N threads writing simultaneously — no rows lost, no DB corruption."""
    store_path = str(tmp_path / "concurrent.sqlite")
    n_threads = 20
    n_writes_per_thread = 25
    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        for i in range(n_writes_per_thread):
            try:
                process_post_tool_use(
                    _post_payload(session_id=f"thread-{thread_id}-session-{i}"),
                    store_path,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent writes raised: {errors[:3]}"

    store = SQLiteEvidenceStore(store_path)
    all_events = store.query(limit=n_threads * n_writes_per_thread + 100)
    store.close()
    assert len(all_events) == n_threads * n_writes_per_thread, (
        f"expected {n_threads * n_writes_per_thread} events, got {len(all_events)}"
    )


@pytest.mark.slow
def test_concurrent_pre_and_post_writes_no_corruption(tmp_path) -> None:
    """PreToolUse and PostToolUse hooks writing concurrently — no corruption."""
    store_path = str(tmp_path / "mixed.sqlite")
    n = 30
    errors: list[Exception] = []

    def pre_worker() -> None:
        for i in range(n):
            try:
                process_pre_tool_use(_pre_payload(session_id=f"mixed-{i}"), store_path, policy=None)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def post_worker() -> None:
        for i in range(n):
            try:
                process_post_tool_use(_post_payload(session_id=f"mixed-{i}"), store_path)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=pre_worker), threading.Thread(target=post_worker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"mixed concurrent writes raised: {errors[:3]}"


# ---------------------------------------------------------------------------
# Large session handling
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_large_session_store_and_retrieve(tmp_path) -> None:
    """1000-event session: write, list, and export stay under resource limits."""
    store_path = str(tmp_path / "large.sqlite")
    n_events = 1000
    session_id = "large-session"

    for i in range(n_events):
        process_post_tool_use(_post_payload(session_id=session_id, cmd=f"echo {i}"), store_path)

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()

    assert len(events) == n_events


@pytest.mark.slow
def test_large_session_does_not_oom(tmp_path) -> None:
    """Session export of 500 events completes without error."""
    import sys
    import subprocess
    import json

    store_path = str(tmp_path / "large.sqlite")
    session_id = "export-stress"

    for i in range(500):
        process_post_tool_use(_post_payload(session_id=session_id, cmd=f"echo {i}"), store_path)

    packages_dir = str(__file__.split("tests/")[0].rstrip("/"))
    result = subprocess.run(
        [sys.executable, "-m", "chp_core.cli", "session", "export", session_id, "--store", store_path],
        capture_output=True, text=True,
        env={"PYTHONPATH": packages_dir, **__import__("os").environ},
    )
    assert result.returncode == 0, f"session export failed: {result.stderr}"
    bundle = json.loads(result.stdout)
    assert bundle["event_count"] == 500


# ---------------------------------------------------------------------------
# Hook performance (p99 contract)
# ---------------------------------------------------------------------------

@pytest.mark.perf
def test_post_tool_hook_p99_under_5ms(tmp_path) -> None:
    """p99 of 100 post-tool hook calls must be < 5ms (warm path)."""
    store_path = str(tmp_path / "perf.sqlite")
    n = 100
    warm_up = 5

    # warm up
    for _ in range(warm_up):
        process_post_tool_use(_post_payload(), store_path)

    latencies: list[float] = []
    for i in range(n):
        t0 = time.perf_counter()
        process_post_tool_use(_post_payload(session_id=f"perf-{i}"), store_path)
        latencies.append((time.perf_counter() - t0) * 1000)

    p99 = statistics.quantiles(latencies, n=100)[98]
    assert p99 < 5.0, f"p99 = {p99:.2f}ms — exceeds 5ms contract"


@pytest.mark.perf
def test_pre_tool_hook_p99_under_5ms(tmp_path) -> None:
    """p99 of 100 pre-tool hook calls must be < 5ms (warm path, no policy)."""
    store_path = str(tmp_path / "perf-pre.sqlite")
    n = 100
    warm_up = 5

    for _ in range(warm_up):
        process_pre_tool_use(_pre_payload(), store_path, policy=None)

    latencies: list[float] = []
    for i in range(n):
        t0 = time.perf_counter()
        process_pre_tool_use(_pre_payload(session_id=f"perf-{i}"), store_path, policy=None)
        latencies.append((time.perf_counter() - t0) * 1000)

    p99 = statistics.quantiles(latencies, n=100)[98]
    assert p99 < 5.0, f"p99 = {p99:.2f}ms — exceeds 5ms contract"


# ---------------------------------------------------------------------------
# Policy evaluation under load
# ---------------------------------------------------------------------------

@pytest.mark.perf
def test_policy_evaluation_with_100_patterns_is_fast() -> None:
    """Policy with 100 block patterns evaluates in < 1ms per call."""
    patterns = [
        BlockPattern(
            capability_id="claude_code.bash",
            field="command",
            pattern=f"forbidden_command_{i}",
            reason=f"blocked pattern {i}",
        )
        for i in range(100)
    ]
    policy = PolicyConfig(block_patterns=patterns)
    tool_input = {"command": "echo hello"}

    n = 500
    t0 = time.perf_counter()
    for _ in range(n):
        evaluate_policy("claude_code.bash", tool_input, policy)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    per_call_ms = elapsed_ms / n

    assert per_call_ms < 1.0, f"policy eval avg {per_call_ms:.3f}ms — too slow for 100 patterns"


@pytest.mark.slow
def test_policy_block_fires_correctly_under_load(tmp_path) -> None:
    """Policy blocks remain accurate across 500 evaluations."""
    store_path = str(tmp_path / "policy-load.sqlite")
    policy = PolicyConfig(
        block_patterns=[
            BlockPattern(
                capability_id="claude_code.bash",
                field="command",
                pattern=r"rm -rf /",
                reason="unscoped deletion",
            )
        ],
    )
    blocked = 0
    passed = 0
    for i in range(500):
        cmd = "rm -rf /" if i % 2 == 0 else "echo hello"
        result = process_pre_tool_use(
            _pre_payload(session_id=f"policy-{i}", cmd=cmd),
            store_path,
            policy=policy,
        )
        if result.should_block:
            blocked += 1
        else:
            passed += 1

    assert blocked == 250, f"expected 250 blocked, got {blocked}"
    assert passed == 250, f"expected 250 passed, got {passed}"
