"""Scheduled retention loop (hardening arc): ticks apply policies and resync
the heads cache; a failing tick never kills the loop."""

from __future__ import annotations

import json
import time

from chp_host import retention


def test_apply_once_purges_and_resyncs_heads(tmp_path):
    from chp_core.store import SQLiteEvidenceStore
    from chp_core.types import CorrelationContext, ExecutionEvidence, new_id

    store_path = str(tmp_path / "ret.sqlite")
    store = SQLiteEvidenceStore(store_path)
    store.append(ExecutionEvidence(
        event_id=new_id("evt"), event_type="execution_started",
        invocation_id=new_id("inv"), capability_id="old.cap",
        capability_version="1.0.0", host_id="ret-host",
        correlation=CorrelationContext(correlation_id="ancient"),
        timestamp="2020-01-01T00:00:00Z", payload={}, redacted=False))
    store.close()

    config = tmp_path / "retention.json"
    config.write_text(json.dumps({"retain_days": 30}))
    summary = retention._apply_once(store_path, str(config))
    assert summary["purged"] >= 1

    check = SQLiteEvidenceStore(store_path)
    try:
        # heads cache resynced: the purged correlation is gone from the head.
        assert "ancient" not in check.get_store_head()["leaves"]
    finally:
        check.close()


def test_loop_ticks_and_survives_failures(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_apply(store_path: str, config_path: str) -> dict:
        calls.append(store_path)
        if len(calls) == 1:
            raise RuntimeError("bad first tick")
        return {"purged": 0, "redacted": 0, "inspected": 0}

    monkeypatch.setattr(retention, "_apply_once", fake_apply)
    stop = retention.start_retention_loop("s.sqlite", "c.json", interval_s=0.05)
    try:
        deadline = time.monotonic() + 5
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stop()
    assert len(calls) >= 2, "the loop must survive a failing tick and keep going"
