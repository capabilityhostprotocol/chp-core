"""Tests for v0.2.7 policy gates: risk tiers, audit-only, allowlist."""

from __future__ import annotations

import pytest

from chp_core.hooks import CAPABILITY_RISK_MAP, process_pre_tool_use
from chp_core.policy import BlockPattern, PolicyConfig, evaluate_policy
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# audit_only mode
# ---------------------------------------------------------------------------

def test_audit_only_never_blocks() -> None:
    policy = PolicyConfig(
        block_capability_ids=["claude_code.bash"],
        audit_only=True,
    )
    result = evaluate_policy("claude_code.bash", {"command": "rm -rf /"}, policy)
    assert result.should_block is False


def test_audit_only_preserves_reason() -> None:
    policy = PolicyConfig(block_capability_ids=["claude_code.bash"], audit_only=True)
    result = evaluate_policy("claude_code.bash", {}, policy)
    assert result.reason is not None  # reason recorded even though not blocking


# ---------------------------------------------------------------------------
# allowlist
# ---------------------------------------------------------------------------

def test_allowlist_blocks_unlisted_capability() -> None:
    policy = PolicyConfig(allowed_capability_ids=["claude_code.read"])
    result = evaluate_policy("claude_code.bash", {}, policy)
    assert result.should_block is True
    assert "allowlist" in (result.reason or "")


def test_allowlist_passes_listed_capability() -> None:
    policy = PolicyConfig(allowed_capability_ids=["claude_code.read", "claude_code.bash"])
    result = evaluate_policy("claude_code.read", {}, policy)
    assert result.should_block is False


def test_allowlist_with_audit_only_never_blocks() -> None:
    policy = PolicyConfig(
        allowed_capability_ids=["claude_code.read"],
        audit_only=True,
    )
    result = evaluate_policy("claude_code.bash", {}, policy)
    assert result.should_block is False


# ---------------------------------------------------------------------------
# max_risk_tier
# ---------------------------------------------------------------------------

def test_max_risk_tier_blocks_high_when_max_is_medium() -> None:
    policy = PolicyConfig(max_risk_tier="medium")
    result = evaluate_policy("codex.delete", {}, policy, capability_risk="high")
    assert result.should_block is True
    assert "high" in (result.reason or "")


def test_max_risk_tier_passes_equal_tier() -> None:
    policy = PolicyConfig(max_risk_tier="medium")
    result = evaluate_policy("claude_code.bash", {}, policy, capability_risk="medium")
    assert result.should_block is False


def test_max_risk_tier_passes_lower_tier() -> None:
    policy = PolicyConfig(max_risk_tier="high")
    result = evaluate_policy("claude_code.read", {}, policy, capability_risk="low")
    assert result.should_block is False


def test_max_risk_tier_no_risk_provided_passes() -> None:
    policy = PolicyConfig(max_risk_tier="low")
    result = evaluate_policy("unknown.cap", {}, policy, capability_risk=None)
    assert result.should_block is False


def test_max_risk_tier_with_audit_only_never_blocks() -> None:
    policy = PolicyConfig(max_risk_tier="low", audit_only=True)
    result = evaluate_policy("claude_code.bash", {}, policy, capability_risk="medium")
    assert result.should_block is False


# ---------------------------------------------------------------------------
# CAPABILITY_RISK_MAP wired into process_pre_tool_use
# ---------------------------------------------------------------------------

def test_risk_map_blocks_high_risk_tool_via_process_pre_tool(tmp_path) -> None:
    store_path = str(tmp_path / "s.sqlite")
    policy = PolicyConfig(max_risk_tier="medium")

    payload = {
        "session_id": "risk-map-test",
        "tool_name": "delete_file",  # maps to codex.delete → risk=high
        "tool_input": {},
        "cwd": "/tmp",
    }
    result = process_pre_tool_use(
        payload,
        store_path,
        policy=policy,
        tool_map={"delete_file": "codex.delete"},
        agent_prefix="codex",
    )
    assert result.should_block is True


def test_risk_map_covers_known_high_risk_capabilities() -> None:
    high_risk = [k for k, v in CAPABILITY_RISK_MAP.items() if v == "high"]
    assert "codex.delete" in high_risk
    assert "gemini.delete" in high_risk
