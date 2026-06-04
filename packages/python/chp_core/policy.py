"""CHP pre-tool policy engine.

Loads a JSON policy file and evaluates whether a tool invocation should be
blocked before it runs. No third-party dependencies — policy files are JSON.

Policy file locations (checked in order):
  1. Explicit path passed to load_policy()
  2. CHP_POLICY_FILE environment variable
  3. .chp/policy.json  (project-local)
  4. ~/.chp/policy.json (global)

Policy file format:
  {
    "version": "1",
    "block_capability_ids": ["claude_code.bash"],
    "max_risk_tier": "medium",
    "audit_only": false,
    "allowed_capability_ids": null,
    "block_patterns": [
      {
        "capability_id": "claude_code.bash",
        "field": "command",
        "pattern": "rm -rf /",
        "reason": "Unscoped deletion blocked by policy"
      }
    ]
  }
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class BlockPattern:
    capability_id: str
    field: str
    pattern: str
    reason: str


@dataclass
class PolicyConfig:
    block_capability_ids: list[str] = field(default_factory=list)
    block_patterns: list[BlockPattern] = field(default_factory=list)
    # v0.2.7 additions
    max_risk_tier: str | None = None
    audit_only: bool = False
    allowed_capability_ids: list[str] | None = None


@dataclass
class PreToolResult:
    should_block: bool
    capability_id: str
    reason: str | None = None


def load_policy(path: str | None = None) -> PolicyConfig | None:
    """Load and parse a CHP policy file. Returns None if no policy is found."""
    candidates: list[Path] = []

    if path:
        candidates.append(Path(path))
    else:
        env = os.environ.get("CHP_POLICY_FILE")
        if env:
            candidates.append(Path(env))
        candidates.append(Path(".chp") / "policy.json")
        candidates.append(Path.home() / ".chp" / "policy.json")

    for candidate in candidates:
        if candidate.exists():
            try:
                with candidate.open() as f:
                    return _parse_policy(json.load(f))
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

    return None


def _parse_policy(data: dict[str, Any]) -> PolicyConfig:
    patterns = [
        BlockPattern(
            capability_id=p["capability_id"],
            field=p["field"],
            pattern=p["pattern"],
            reason=p.get("reason", "blocked by policy pattern"),
        )
        for p in data.get("block_patterns", [])
    ]
    allowed = data.get("allowed_capability_ids")
    return PolicyConfig(
        block_capability_ids=list(data.get("block_capability_ids", [])),
        block_patterns=patterns,
        max_risk_tier=data.get("max_risk_tier"),
        audit_only=bool(data.get("audit_only", False)),
        allowed_capability_ids=list(allowed) if allowed is not None else None,
    )


def evaluate_policy(
    capability_id: str,
    tool_input: dict[str, Any],
    policy: PolicyConfig,
    *,
    capability_risk: str | None = None,
) -> PreToolResult:
    """Check whether the capability invocation is blocked by the policy.

    Args:
        capability_id: The capability being invoked.
        tool_input: The tool's input dict (used for pattern matching).
        policy: The active policy configuration.
        capability_risk: Optional risk tier of the capability (low/medium/high/critical).
            Required for max_risk_tier evaluation.
    """
    should_block = False
    reason: str | None = None

    # Allowlist: if set, block anything NOT in the list
    if policy.allowed_capability_ids is not None:
        if capability_id not in policy.allowed_capability_ids:
            should_block = True
            reason = f"capability not in allowlist: {capability_id}"

    # Exact capability ID block
    if not should_block and capability_id in policy.block_capability_ids:
        should_block = True
        reason = f"capability blocked by policy: {capability_id}"

    # Risk tier: block if capability risk exceeds the configured maximum
    if not should_block and policy.max_risk_tier is not None and capability_risk is not None:
        cap_order = RISK_ORDER.get(capability_risk, -1)
        max_order = RISK_ORDER.get(policy.max_risk_tier, 99)
        if cap_order > max_order:
            should_block = True
            reason = (
                f"capability risk '{capability_risk}' exceeds "
                f"max_risk_tier '{policy.max_risk_tier}'"
            )

    # Pattern match on tool input fields
    if not should_block:
        for bp in policy.block_patterns:
            if bp.capability_id != capability_id:
                continue
            value = str(tool_input.get(bp.field, ""))
            try:
                matched = bool(re.search(bp.pattern, value))
            except re.error:
                matched = bp.pattern in value
            if matched:
                should_block = True
                reason = bp.reason
                break

    # audit_only overrides any block decision
    if policy.audit_only:
        return PreToolResult(should_block=False, capability_id=capability_id, reason=reason)

    return PreToolResult(should_block=should_block, capability_id=capability_id, reason=reason)
