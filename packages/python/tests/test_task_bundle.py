"""Tests for task bundles — cross-host verification unit (chp-v0.2.md §8)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from chp_core import signing

VEC = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "task-bundle.json"


def _task() -> dict:
    return json.loads(VEC.read_text())


def test_published_task_bundle_verifies():
    v = signing.verify_task_bundle(_task())
    assert v.valid and v.assurance == "signed"
    assert all(v.checks.values()), v.checks
    assert [h["host_id"] for h in v.hosts] == ["task-host-a", "task-host-b"]
    assert all(h["valid"] and h["key_id"] for h in v.hosts)


def test_tampered_member_fails_members_valid():
    t = copy.deepcopy(_task())
    t["bundles"][0]["events"][0]["payload"] = {"n": 999}
    v = signing.verify_task_bundle(t)
    assert not v.valid and v.checks["members_valid"] is False
    # per-host surface points at the culprit
    assert v.hosts[0]["valid"] is False and v.hosts[1]["valid"] is True


def test_dropped_causal_ancestor_fails_closure():
    # Remove host-a (the cause) — host-b's causation_ids dangle.
    t = copy.deepcopy(_task())
    t["bundles"] = [b for b in t["bundles"] if b["host_id"] != "task-host-a"]
    t["task_root_hash"] = signing.compute_task_root_hash(t["bundles"])  # attacker recomputes
    v = signing.verify_task_bundle(t)
    assert not v.valid
    assert v.checks["causal_closure"] is False
    assert "dangling" in (v.reason or "")


def test_member_swap_breaks_task_root_hash():
    t = copy.deepcopy(_task())
    t["bundles"] = list(reversed(t["bundles"]))  # violates canonical order
    v = signing.verify_task_bundle(t)
    assert not v.valid
    assert v.checks["member_order"] is False
    assert v.checks["task_root_hash"] is False  # order feeds the root


def test_min_assurance_surfaced():
    t = copy.deepcopy(_task())
    # degrade one member to hash-chain (strip signature material)
    b = t["bundles"][0]
    for k in ("signature", "public_key", "host_identity"):
        b.pop(k, None)
    b["assurance"] = "hash-chain"
    rebuilt = signing.build_task_bundle(t["correlation_id"], t["bundles"],
                                        created_at=t["created_at"])
    assert rebuilt["assurance"] == "hash-chain"  # min member tier, not hidden


def test_duplicate_host_fails_distinct():
    t = copy.deepcopy(_task())
    t["bundles"] = sorted(t["bundles"] + [copy.deepcopy(t["bundles"][0])],
                          key=lambda b: (b.get("host_id", ""), b.get("root_hash", "")))
    t["task_root_hash"] = signing.compute_task_root_hash(t["bundles"])
    v = signing.verify_task_bundle(t)
    assert not v.valid and v.checks["distinct_hosts"] is False
