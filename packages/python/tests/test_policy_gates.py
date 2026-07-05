"""Tests for v0.2.7 policy gates: risk tiers, audit-only, allowlist."""

from __future__ import annotations

import pytest

from chp_core.hooks import CAPABILITY_RISK_MAP, process_pre_tool_use
from chp_core.host import LocalCapabilityHost
from chp_core.policy import (
    BlockPattern,
    PolicyConfig,
    PolicyError,
    evaluate_policy,
    load_policy,
)
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import CapabilityDescriptor


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


def test_max_risk_tier_unknown_risk_defaults_to_medium_and_blocks() -> None:
    # Fail-closed: an uncharacterised capability (no/unknown risk) is treated as
    # "medium", so a max_risk_tier of "low" blocks it rather than passing it
    # through un-gated (previously a fail-open bypass).
    policy = PolicyConfig(max_risk_tier="low")
    result = evaluate_policy("unknown.cap", {}, policy, capability_risk=None)
    assert result.should_block is True


def test_max_risk_tier_unknown_risk_passes_when_max_is_medium() -> None:
    # Default "medium" does not exceed a "medium" ceiling — still allowed.
    policy = PolicyConfig(max_risk_tier="medium")
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


# ---------------------------------------------------------------------------
# Policy enforced on the host invocation path (not just the Claude Code hook)
# ---------------------------------------------------------------------------

def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_host_blocks_capability_on_invoke_path() -> None:
    async def handler(_ctx, _payload):
        return {"ran": True}

    host = LocalCapabilityHost(
        store=SQLiteEvidenceStore(":memory:"),
        policy=PolicyConfig(block_capability_ids=["danger.cap"]),
    )
    host.register(CapabilityDescriptor(id="danger.cap", version="1.0.0", description=""), handler)
    result = _run(host.ainvoke("danger.cap", {}, correlation={"correlation_id": "c1"}))
    assert result.outcome == "denied"
    assert result.success is False


def test_host_allows_unblocked_capability_on_invoke_path() -> None:
    async def handler(_ctx, _payload):
        return {"ran": True}

    host = LocalCapabilityHost(
        store=SQLiteEvidenceStore(":memory:"),
        policy=PolicyConfig(block_capability_ids=["other.cap"]),
    )
    host.register(CapabilityDescriptor(id="safe.cap", version="1.0.0", description=""), handler)
    result = _run(host.ainvoke("safe.cap", {}, correlation={"correlation_id": "c2"}))
    assert result.success is True


def test_host_no_policy_does_not_block() -> None:
    async def handler(_ctx, _payload):
        return {"ran": True}

    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"), policy=None)
    host.register(CapabilityDescriptor(id="any.cap", version="1.0.0", description=""), handler)
    result = _run(host.ainvoke("any.cap", {}, correlation={"correlation_id": "c3"}))
    assert result.success is True


def test_load_policy_fails_closed_on_malformed_file(tmp_path) -> None:
    bad = tmp_path / "policy.json"
    bad.write_text("{ this is not valid json")
    with pytest.raises(PolicyError):
        load_policy(str(bad))
