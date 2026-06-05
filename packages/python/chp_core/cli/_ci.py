"""CI gate and policy linter CLI commands."""

from __future__ import annotations

import argparse
import json
import re
import sys


_VALID_RISK_TIERS = {"low", "medium", "high", "critical"}


# ── chp policy lint ──────────────────────────────────────────────────────────

def cmd_policy_lint(args: argparse.Namespace) -> int:
    """Validate a CHP policy JSON file."""
    from ..policy import load_policy as _load_raw

    path = getattr(args, "policy_file", None)

    # Load and parse raw JSON for structural validation
    try:
        if path:
            with open(path) as f:
                data = json.load(f)
        else:
            # Try default locations
            from pathlib import Path
            for candidate in (Path(".chp/policy.json"), Path.home() / ".chp" / "policy.json"):
                if candidate.exists():
                    path = str(candidate)
                    with candidate.open() as f:
                        data = json.load(f)
                    break
            else:
                print("No policy file found. Specify a path or create .chp/policy.json", file=sys.stderr)
                return 1
    except FileNotFoundError:
        print(f"Policy file not found: {path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []

    # max_risk_tier
    mrt = data.get("max_risk_tier")
    if mrt is not None and mrt not in _VALID_RISK_TIERS:
        errors.append(f"max_risk_tier '{mrt}' is not one of: {', '.join(sorted(_VALID_RISK_TIERS))}")

    # block_capability_ids
    bcids = data.get("block_capability_ids", [])
    if not isinstance(bcids, list):
        errors.append("block_capability_ids must be a list")
    else:
        for i, v in enumerate(bcids):
            if not isinstance(v, str) or not v:
                errors.append(f"block_capability_ids[{i}] must be a non-empty string")

    # allowed_capability_ids
    acids = data.get("allowed_capability_ids")
    if acids is not None:
        if not isinstance(acids, list):
            errors.append("allowed_capability_ids must be a list or null")
        else:
            for i, v in enumerate(acids):
                if not isinstance(v, str) or not v:
                    errors.append(f"allowed_capability_ids[{i}] must be a non-empty string")

    # block_patterns
    patterns = data.get("block_patterns", [])
    if not isinstance(patterns, list):
        errors.append("block_patterns must be a list")
    else:
        for i, bp in enumerate(patterns):
            prefix = f"block_patterns[{i}]"
            for field in ("capability_id", "field", "pattern", "reason"):
                v = bp.get(field)
                if not isinstance(v, str) or not v:
                    errors.append(f"{prefix}.{field} must be a non-empty string")
            # Validate regex compiles
            pattern_val = bp.get("pattern", "")
            if isinstance(pattern_val, str) and pattern_val:
                try:
                    re.compile(pattern_val)
                except re.error as exc:
                    errors.append(f"{prefix}.pattern is not a valid regex: {exc}")

    n_checks = (
        1  # JSON parse
        + (1 if mrt is not None else 0)
        + len(bcids if isinstance(bcids, list) else [])
        + len(patterns if isinstance(patterns, list) else [])
    )

    if errors:
        print(f"Policy lint FAILED ({len(errors)} error(s)):")
        for err in errors:
            print(f"  • {err}")
        return 1

    src = path or "(default location)"
    print(f"Policy lint OK  —  {src}  —  {n_checks} check(s) passed")
    return 0


# ── chp ci check ─────────────────────────────────────────────────────────────

def cmd_ci_check(args: argparse.Namespace) -> int:
    """Retrospective policy evaluation against stored session evidence."""
    from ..hooks import CAPABILITY_RISK_MAP
    from ..policy import evaluate_policy, load_policy
    from ..store import SQLiteEvidenceStore

    store_path: str | None = getattr(args, "store", None)
    policy_path: str | None = getattr(args, "policy", None)
    session_id: str | None = getattr(args, "session", None)
    since: str | None = getattr(args, "since", None)
    fail_on_denied: bool = getattr(args, "fail_on_denied", False)

    if store_path is None:
        from ..hooks import default_store_path
        store_path = default_store_path()

    policy = load_policy(policy_path)
    if policy is None:
        print("No policy loaded — nothing to check. Use --policy FILE or create .chp/policy.json")
        return 0

    store = SQLiteEvidenceStore(store_path)
    try:
        if session_id:
            session_ids = [session_id]
        else:
            # Discover all recorded sessions from session_completed events
            query_kwargs: dict = {"capability_id": "claude_code.session"}
            if since:
                query_kwargs["since"] = since
            session_events = store.query(**query_kwargs)
            session_ids = [
                (ev.get("correlation") or {}).get("correlation_id", "")
                for ev in session_events
            ]
            session_ids = [s for s in session_ids if s]

        if not session_ids:
            print("No sessions found to check.")
            return 0

        total_violations = 0
        print(f"\nChecking {len(session_ids)} session(s) against policy...\n")
        print(f"{'SESSION':<36}  {'SEQ':>4}  {'CAPABILITY':<36}  {'INPUT':<30}  VERDICT")
        print("-" * 120)

        for sid in session_ids:
            events = store.by_correlation(sid)
            tool_events = [e for e in events if e["event_type"] == "tool_use_requested"]
            for ev in tool_events:
                seq = ev.get("sequence", "?")
                cap_id = ev.get("capability_id") or ""
                payload = ev.get("payload") or {}
                tool_input = payload.get("tool_input") or {}
                cap_risk = CAPABILITY_RISK_MAP.get(cap_id)

                result = evaluate_policy(cap_id, tool_input, policy, capability_risk=cap_risk)

                if result.should_block or (fail_on_denied and payload.get("blocked")):
                    total_violations += 1
                    verdict = f"BLOCK  {result.reason or ''}"
                else:
                    verdict = "PASS"

                inp = _input_preview(tool_input)
                print(f"{sid:<36}  {str(seq):>4}  {cap_id:<36}  {inp:<30}  {verdict}")
    finally:
        store.close()

    print()
    if total_violations:
        print(f"CI check FAILED — {total_violations} violation(s) found.")
        return 1
    print("CI check PASSED — no violations.")
    return 0


def _input_preview(tool_input: dict) -> str:
    for key in ("command", "file_path", "url", "query", "pattern", "path"):
        val = tool_input.get(key)
        if val:
            return f"{key}={str(val)[:28]!r}"
    if tool_input:
        return json.dumps(tool_input)[:30]
    return "(empty)"
