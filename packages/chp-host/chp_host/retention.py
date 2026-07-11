"""Scheduled evidence retention (hardening arc): the prober-pattern daemon
loop around ``compliance.apply_retention`` — retention stops being a manual
operator act without changing what retention IS (chain-preserving purge /
redact per chp-v0.2 §12 dispositions). Off by default
(``gateway.retention_interval_s``)."""

from __future__ import annotations

import asyncio  # noqa: F401 — parity with sibling loops; retention is sync
import json
import threading


def _apply_once(store_path: str, config_path: str) -> dict:
    from chp_core.compliance import SQLiteComplianceManager
    from chp_core.store import SQLiteEvidenceStore
    from chp_core.types import RetentionPolicy

    with open(config_path) as fh:
        cfg = json.load(fh)
    if cfg.get("policies"):
        policies = [RetentionPolicy(**p) for p in cfg["policies"]]
    else:
        policies = [RetentionPolicy(
            policy_id="default", applies_to=["*"],
            retain_days=int(cfg.get("retain_days", 30)),
            redact_payload_after_days=cfg.get("redact_payload_after_days"),
        )]
    store = SQLiteEvidenceStore(store_path)
    try:
        report = SQLiteComplianceManager(store).apply_retention(policies)
        # Contract: retention mutations must resync the serving heads cache.
        store.rebuild_heads()
        return {"purged": report.events_purged, "redacted": report.events_redacted,
                "inspected": report.events_inspected}
    finally:
        store.close()


def start_retention_loop(store_path: str, config_path: str, interval_s: float):
    """Daemon thread applying retention every *interval_s* seconds. A failed
    tick logs and keeps looping. Returns a zero-arg stop callable."""
    stop = threading.Event()

    def _loop() -> None:
        while not stop.wait(interval_s):
            try:
                summary = _apply_once(store_path, config_path)
                print(f"retention tick: {summary}", flush=True)
            except Exception as exc:  # noqa: BLE001 — a bad tick must not kill the loop
                print(f"retention tick failed: {exc}", flush=True)

    threading.Thread(target=_loop, daemon=True, name="chp-retention").start()
    return stop.set
