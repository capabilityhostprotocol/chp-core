"""Multi-agent session tree rendering with per-node chain integrity."""

from __future__ import annotations

import sys

_ANSI  = sys.stdout.isatty()
_GREEN = "\033[32m" if _ANSI else ""
_RED   = "\033[31m" if _ANSI else ""
_DIM   = "\033[2m"  if _ANSI else ""
_RESET = "\033[0m"  if _ANSI else ""


def render_tree(session_id: str, store_path: str, depth: int = 10) -> None:
    """Print the multi-agent session tree rooted at session_id."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        print()
        _render_node(session_id, store, max_depth=depth, current_depth=0, visited=set())
    finally:
        store.close()


def _render_node(
    session_id: str,
    store: "SQLiteEvidenceStore",
    max_depth: int,
    current_depth: int,
    visited: set[str],
) -> None:
    if current_depth > max_depth or session_id in visited:
        return
    visited.add(session_id)

    events     = store.by_correlation(session_id)
    chain      = store.verify_chain(session_id)
    tool_count = sum(1 for e in events if e["event_type"] == "tool_use")
    spawn_count = sum(1 for e in events if e["event_type"] == "session_spawn")

    chain_icon = (
        f"{_GREEN}[chain:ok]{_RESET}"
        if chain.valid
        else f"{_RED}[chain:BROKEN at seq {chain.first_broken_sequence}]{_RESET}"
    )
    indent  = "  " * current_depth
    prefix  = "└─ " if current_depth > 0 else ""
    spawns  = f"  {_DIM}spawns={spawn_count}{_RESET}" if spawn_count else ""
    print(f"{indent}{prefix}{session_id}  tools={tool_count}{spawns}  {chain_icon}")

    for child_id in store.children_of(session_id):
        _render_node(child_id, store, max_depth, current_depth + 1, visited)
