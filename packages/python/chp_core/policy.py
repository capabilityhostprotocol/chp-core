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
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PolicyError(ValueError):
    """A policy file exists but could not be parsed — treated as fail-closed."""


RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The policy decision vocabulary (chp-governance-v0.2.md §2, proposal 0036). ALLOW
# proceeds; the rest block the invocation at the governance gate, each mapping to a
# reserved denial code (see host.py DECISION_CODE). SANDBOX_ONLY is a constrained-
# allow, but with no sandbox execution mode it fails closed to a deny (policy_blocked).
POLICY_DECISIONS: frozenset[str] = frozenset({
    "allow", "deny", "requires_approval", "requires_escalation",
    "requires_more_evidence", "sandbox_only",
})

# What the caller must do to unblock a non-allow, non-deny decision.
REQUIRED_NEXT_ACTION: dict[str, str] = {
    "requires_approval": "obtain human approval and retry",
    "requires_escalation": "escalate to a higher authority to decide",
    "requires_more_evidence": "provide the required additional evidence and retry",
    "sandbox_only": "run in a sandbox (no sandbox execution mode available — denied)",
}


@dataclass
class BlockPattern:
    capability_id: str
    field: str
    pattern: str
    reason: str
    # The decision this rule renders when it matches (proposal 0036). Default "deny"
    # keeps every pre-0036 policy file behaving exactly as before.
    decision: str = "deny"


@dataclass
class PolicyConfig:
    block_capability_ids: list[str] = field(default_factory=list)
    block_patterns: list[BlockPattern] = field(default_factory=list)
    # v0.2.7 additions
    max_risk_tier: str | None = None
    audit_only: bool = False
    allowed_capability_ids: list[str] | None = None
    # Policy file version, threaded into every decision record (proposal 0036).
    version: str | None = None


@dataclass
class PreToolResult:
    should_block: bool
    capability_id: str
    reason: str | None = None
    # Decision record (proposal 0036): the outcome, the rule that produced it, the
    # policy version, and the caller's required next action. `should_block` stays the
    # block signal (derived: True unless decision == "allow", and never when audit_only).
    decision: str = "allow"
    matched_rule: str | None = None
    policy_version: str | None = None
    required_next_action: str | None = None


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
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                # Fail closed: a policy file that exists but can't be parsed must
                # not silently disable all blocking. Surface it loudly.
                logger.error("policy file %s is unparseable: %s", candidate, exc)
                raise PolicyError(f"unparseable policy file {candidate}: {exc}") from exc

    return None


def _parse_policy(data: dict[str, Any]) -> PolicyConfig:
    patterns = []
    for p in data.get("block_patterns", []):
        decision = p.get("decision", "deny")
        if decision not in POLICY_DECISIONS:
            raise PolicyError(f"unknown policy decision {decision!r} (allowed: {sorted(POLICY_DECISIONS)})")
        patterns.append(BlockPattern(
            capability_id=p["capability_id"],
            field=p["field"],
            pattern=p["pattern"],
            reason=p.get("reason", "blocked by policy pattern"),
            decision=decision,
        ))
    allowed = data.get("allowed_capability_ids")
    version = data.get("version")
    return PolicyConfig(
        block_capability_ids=list(data.get("block_capability_ids", [])),
        block_patterns=patterns,
        max_risk_tier=data.get("max_risk_tier"),
        audit_only=bool(data.get("audit_only", False)),
        allowed_capability_ids=list(allowed) if allowed is not None else None,
        version=str(version) if version is not None else None,
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
    # decision is "allow" until a rule fires; the coarse rules (allowlist, block-id,
    # risk tier) always render "deny", while a block-pattern may render any decision
    # in the vocabulary (proposal 0036). matched_rule names the rule that fired.
    decision = "allow"
    reason: str | None = None
    matched_rule: str | None = None

    # Allowlist: if set, block anything NOT in the list
    if policy.allowed_capability_ids is not None:
        if capability_id not in policy.allowed_capability_ids:
            decision = "deny"
            reason = f"capability not in allowlist: {capability_id}"
            matched_rule = "allowed_capability_ids"

    # Exact capability ID block
    if decision == "allow" and capability_id in policy.block_capability_ids:
        decision = "deny"
        reason = f"capability blocked by policy: {capability_id}"
        matched_rule = f"block_capability_ids:{capability_id}"

    # Risk tier: block if capability risk exceeds the configured maximum.
    # Unmapped/unknown capability risk defaults to "medium" so the gate still
    # bites rather than silently passing an uncharacterised capability.
    if decision == "allow" and policy.max_risk_tier is not None:
        effective_risk = capability_risk if capability_risk in RISK_ORDER else "medium"
        cap_order = RISK_ORDER.get(effective_risk, 1)
        max_order = RISK_ORDER.get(policy.max_risk_tier, 99)
        if cap_order > max_order:
            decision = "deny"
            reason = (
                f"capability risk '{effective_risk}' exceeds "
                f"max_risk_tier '{policy.max_risk_tier}'"
            )
            matched_rule = f"max_risk_tier:{policy.max_risk_tier}"

    # Pattern match on tool input fields. Case-insensitive so trivial casing
    # ("RM -RF /") can't slip past a lowercase rule; patterns are
    # defense-in-depth, not a sandbox. A matched pattern renders its declared
    # decision (default "deny").
    if decision == "allow":
        for bp in policy.block_patterns:
            if bp.capability_id != capability_id:
                continue
            value = str(tool_input.get(bp.field, ""))
            try:
                matched = bool(re.search(bp.pattern, value, re.IGNORECASE))
            except re.error:
                matched = bp.pattern.lower() in value.lower()
            if matched:
                decision = bp.decision
                reason = bp.reason
                matched_rule = f"block_pattern:{bp.capability_id}.{bp.field}"
                break

    # audit_only records the decision but never blocks — the decision is advisory.
    should_block = (decision != "allow") and not policy.audit_only
    return PreToolResult(
        should_block=should_block,
        capability_id=capability_id,
        reason=reason,
        decision=decision,
        matched_rule=matched_rule,
        policy_version=policy.version,
        required_next_action=REQUIRED_NEXT_ACTION.get(decision),
    )
