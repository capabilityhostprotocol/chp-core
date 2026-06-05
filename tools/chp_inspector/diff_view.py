"""Side-by-side session comparison."""

from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime

_ANSI   = sys.stdout.isatty()
_GREEN  = "\033[32m" if _ANSI else ""
_RED    = "\033[31m" if _ANSI else ""
_YELLOW = "\033[33m" if _ANSI else ""
_DIM    = "\033[2m"  if _ANSI else ""
_RESET  = "\033[0m"  if _ANSI else ""


def diff_sessions(session_a: str, session_b: str, store_path: str) -> None:
    """Print a side-by-side comparison of two CHP sessions."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        ev_a = store.by_correlation(session_a)
        ev_b = store.by_correlation(session_b)
        chain_a = store.verify_chain(session_a)
        chain_b = store.verify_chain(session_b)
    finally:
        store.close()

    if not ev_a:
        print(f"No events found for session: {session_a}")
        return
    if not ev_b:
        print(f"No events found for session: {session_b}")
        return

    def _stats(events):
        tools    = [e for e in events if e["event_type"] == "tool_use"]
        failures = [e for e in events if e.get("outcome") == "failure"]
        denied   = [e for e in events if e.get("outcome") == "denied"]
        ts = [e["timestamp"] for e in events if e.get("timestamp")]
        dur: float | None = None
        if len(ts) >= 2:
            def _p(t):
                return datetime.fromisoformat(t.replace("Z", "+00:00"))
            dur = (_p(ts[-1]) - _p(ts[0])).total_seconds()
        cap_counts: dict[str, int] = defaultdict(int)
        for e in tools:
            cap = e.get("capability_id") or ""
            if cap:
                cap_counts[cap] += 1
        return {
            "events": len(events),
            "tools": len(tools),
            "failures": len(failures),
            "denied": len(denied),
            "duration": dur,
            "caps": cap_counts,
        }

    sa, sb = _stats(ev_a), _stats(ev_b)

    w = 26  # column width

    def _chain(c):
        return f"{_GREEN}ok{_RESET}" if c.valid else f"{_RED}BROKEN@{c.first_broken_sequence}{_RESET}"

    print(f"\n{'':24}  {session_a[:w]:<{w}}  {session_b[:w]:<{w}}")
    print("-" * (24 + 2 + w + 2 + w))

    def _row(label, va, vb, fmt=str):
        a_str = fmt(va) if va is not None else "—"
        b_str = fmt(vb) if vb is not None else "—"
        print(f"  {label:<22}  {a_str:<{w}}  {b_str:<{w}}")

    _row("events", sa["events"], sb["events"])
    _row("tool calls", sa["tools"], sb["tools"])
    _row("failures", sa["failures"], sb["failures"])
    _row("denied", sa["denied"], sb["denied"])
    dur_a = f"{sa['duration']:.1f}s" if sa["duration"] is not None else "—"
    dur_b = f"{sb['duration']:.1f}s" if sb["duration"] is not None else "—"
    print(f"  {'duration':<22}  {dur_a:<{w}}  {dur_b:<{w}}")
    ca_str = f"{_GREEN}ok{_RESET}" if chain_a.valid else f"{_RED}BROKEN@{chain_a.first_broken_sequence}{_RESET}"
    cb_str = f"{_GREEN}ok{_RESET}" if chain_b.valid else f"{_RED}BROKEN@{chain_b.first_broken_sequence}{_RESET}"
    print(f"  {'chain':<22}  {ca_str:<{w + 10}}  {cb_str}")

    # Capability delta
    all_caps = sorted(set(sa["caps"]) | set(sb["caps"]))
    if all_caps:
        print(f"\n  {_DIM}{'CAPABILITY':<40}  {'A':>6}  {'B':>6}  DELTA{_RESET}")
        print("  " + "-" * 62)
        for cap in all_caps:
            cnt_a = sa["caps"].get(cap, 0)
            cnt_b = sb["caps"].get(cap, 0)
            delta = cnt_b - cnt_a
            if delta > 0:
                d_str = f"{_GREEN}+{delta}{_RESET}"
                tag = f"  {_GREEN}(new){_RESET}" if cnt_a == 0 else ""
            elif delta < 0:
                d_str = f"{_RED}{delta}{_RESET}"
                tag = f"  {_RED}(removed){_RESET}" if cnt_b == 0 else ""
            else:
                d_str = f"{_DIM}={_RESET}"
                tag = ""
            print(f"  {cap:<40}  {cnt_a:>6}  {cnt_b:>6}  {d_str}{tag}")
