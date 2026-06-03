"""CHP pre-tool policy engine for v0.2.2.

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
    return PolicyConfig(
        block_capability_ids=list(data.get("block_capability_ids", [])),
        block_patterns=patterns,
    )


def evaluate_policy(
    capability_id: str,
    tool_input: dict[str, Any],
    policy: PolicyConfig,
) -> PreToolResult:
    """Check whether the capability invocation is blocked by the policy."""
    # Fast path: exact capability ID block
    if capability_id in policy.block_capability_ids:
        return PreToolResult(
            should_block=True,
            capability_id=capability_id,
            reason=f"capability blocked by policy: {capability_id}",
        )

    # Pattern match on tool input fields
    for bp in policy.block_patterns:
        if bp.capability_id != capability_id:
            continue
        value = str(tool_input.get(bp.field, ""))
        try:
            matched = bool(re.search(bp.pattern, value))
        except re.error:
            matched = bp.pattern in value
        if matched:
            return PreToolResult(
                should_block=True,
                capability_id=capability_id,
                reason=bp.reason,
            )

    return PreToolResult(should_block=False, capability_id=capability_id)
