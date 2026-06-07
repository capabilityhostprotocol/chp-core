"""Tests for SQLiteComplianceManager and compliance capability — §8.5."""

from __future__ import annotations

import os
import tempfile

import pytest

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.compliance import SQLiteComplianceManager, register_compliance_capability
from chp_core.types import RetentionPolicy


async def _seed(host: LocalCapabilityHost, count: int = 3) -> None:
    for i in range(count):
        await host.ainvoke("test.noop", {}, correlation={"correlation_id": f"seed-{i}"})


@pytest.fixture
async def seeded_host():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        path = f.name
    store = SQLiteEvidenceStore(path)
    host = LocalCapabilityHost("test-compliance", store=store)

    async def _noop(ctx, payload):
        return {"ok": True}

    host.register(
        CapabilityDescriptor(id="test.noop", version="1.0.0", description="noop"),
        _noop,
    )
    await _seed(host, 3)
    yield store, host
    store.close()
    os.unlink(path)


@pytest.mark.asyncio
async def test_generate_report_returns_nonzero_count(seeded_host):
    store, _ = seeded_host
    manager = SQLiteComplianceManager(store)
    report = manager.generate_report()
    assert report.events_inspected > 0
    assert report.events_purged == 0
    assert report.events_redacted == 0
    assert report.report_id.startswith("cr_")


@pytest.mark.asyncio
async def test_apply_retention_purges_matching_events(seeded_host):
    store, _ = seeded_host
    manager = SQLiteComplianceManager(store)
    initial_count = store.count()

    policy = RetentionPolicy(
        policy_id="test-purge",
        retain_days=0,
        applies_to=["test.noop"],
    )
    report = manager.apply_retention([policy])
    assert report.events_purged > 0
    assert store.count() < initial_count
    assert "test-purge" in report.policy_ids


@pytest.mark.asyncio
async def test_apply_retention_wildcard_purges_all(seeded_host):
    store, _ = seeded_host
    manager = SQLiteComplianceManager(store)
    initial_count = store.count()

    policy = RetentionPolicy(
        policy_id="purge-all",
        retain_days=0,
        applies_to=["*"],
    )
    report = manager.apply_retention([policy])
    assert report.events_purged == initial_count
    assert store.count() == 0


@pytest.mark.asyncio
async def test_apply_retention_non_matching_pattern_is_noop(seeded_host):
    store, _ = seeded_host
    manager = SQLiteComplianceManager(store)
    initial_count = store.count()

    policy = RetentionPolicy(
        policy_id="no-match",
        retain_days=0,
        applies_to=["does.not.exist"],
    )
    report = manager.apply_retention([policy])
    assert report.events_purged == 0
    assert store.count() == initial_count


@pytest.mark.asyncio
async def test_purge_by_pattern(seeded_host):
    store, _ = seeded_host
    manager = SQLiteComplianceManager(store)
    from datetime import datetime, timezone
    before_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    count = manager.purge("test.noop", before_ts)
    assert count > 0
    assert store.count() == 0


@pytest.mark.asyncio
async def test_compliance_via_host(seeded_host):
    store, host = seeded_host
    manager = SQLiteComplianceManager(store)
    register_compliance_capability(host, manager)

    r_report = await host.ainvoke("compliance.report", {})
    assert r_report.success
    assert r_report.data["events_inspected"] > 0

    r_apply = await host.ainvoke(
        "compliance.apply_retention",
        {
            "policies": [
                {
                    "policy_id": "via-host",
                    "retain_days": 0,
                    "applies_to": ["test.noop"],
                }
            ]
        },
    )
    assert r_apply.success
    assert r_apply.data["events_purged"] > 0
