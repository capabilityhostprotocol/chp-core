"""Retrospective policy evaluation against stored session evidence."""

from __future__ import annotations

import json
import sys

_ANSI  = sys.stdout.isatty()
_GREEN = "\033[32m" if _ANSI else ""
_RED   = "\033[31m" if _ANSI else ""
_RESET = "\033[0m"  if _ANSI else ""


def policy_check_session(
    session_id: str,
    store_path: str,
    policy_path: str,
) -> int:
    """Evaluate a policy file against every tool_use_requested event in session.

    Prints: seq | capability_id | input_preview | PASS / BLOCK (reason)
    Returns 1 if any event would be blocked, 0 otherwise.
    """
    from chp_core.hooks import CAPABILITY_RISK_MAP
    from chp_core.policy import evaluate_policy, load_policy
    from chp_core.store import SQLiteEvidenceStore

    policy = load_policy(policy_path)
    if policy is None:
        print(f"Could not load policy from: {policy_path}")
        return 1

    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(session_id)
    finally:
        store.close()

    tool_events = [e for e in events if e["event_type"] == "tool_use_requested"]

    if not tool_events:
        print(f"No tool_use_requested events for session: {session_id}")
        return 0

    any_blocked = False
    print(
        f"\n{'SEQ':>5}  {'CAPABILITY':<40}  {'INPUT':<35}  VERDICT"
    )
    print("-" * 100)

    for ev in tool_events:
        seq        = ev.get("sequence", "?")
        cap_id     = ev.get("capability_id") or ""
        payload    = ev.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        cap_risk   = CAPABILITY_RISK_MAP.get(cap_id)

        result = evaluate_policy(cap_id, tool_input, policy, capability_risk=cap_risk)

        # Compact single-field preview of tool_input
        inp_preview = _input_preview(tool_input)

        if result.should_block:
            any_blocked = True
            verdict = f"{_RED}BLOCK{_RESET}  {result.reason or ''}"
        else:
            verdict = f"{_GREEN}PASS{_RESET}"

        print(f"{str(seq):>5}  {cap_id:<40}  {inp_preview:<35}  {verdict}")

    print()
    if any_blocked:
        print(f"{_RED}Policy check FAILED — one or more tool calls would be blocked.{_RESET}")
        return 1
    else:
        print(f"{_GREEN}Policy check PASSED — no tool calls would be blocked.{_RESET}")
        return 0


def _input_preview(tool_input: dict) -> str:
    """Return a short human-readable snippet of the tool input."""
    for key in ("command", "file_path", "url", "query", "pattern", "path"):
        val = tool_input.get(key)
        if val:
            snippet = str(val)[:33]
            return f"{key}={snippet!r}"
    if tool_input:
        raw = json.dumps(tool_input)[:33]
        return raw
    return "(empty)"
