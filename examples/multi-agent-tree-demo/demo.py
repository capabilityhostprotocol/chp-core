"""Multi-agent correlation tree demo (v0.2.3 + v0.2.6).

Shows how CHP tracks parent-child agent relationships when one session
spawns sub-agents, and how to reconstruct the session tree with hash-chain
verification at every level.

The session_spawn mechanism mirrors exactly what Claude Code produces when
the Agent tool is used: a post-tool hook with tool_name="Agent" and a
tool_response containing "session_id" automatically emits a session_spawn
event linking parent to child.

Run:
    PYTHONPATH=packages/python python examples/multi-agent-tree-demo/demo.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from chp_core.hooks import process_post_tool_use, process_stop
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import CorrelationContext


def simulate_session(
    store_path: str,
    session_id: str,
    tools: list[tuple[str, dict, dict]],
) -> None:
    """Record a session's tool calls exactly as Claude Code hooks would."""
    for tool_name, tool_input, tool_response in tools:
        process_post_tool_use(
            {
                "session_id": session_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "tool_response": tool_response,
                "cwd": "/workspace",
            },
            store_path,
        )
    process_stop({"session_id": session_id, "transcript_path": ""}, store_path)


def print_tree(store: SQLiteEvidenceStore, session_id: str, depth: int = 0) -> None:
    """Recursively print the session tree with per-node chain integrity status."""
    events = store.by_correlation(session_id)
    chain = store.verify_chain(session_id)
    tool_count = sum(1 for e in events if e["event_type"] == "tool_use")
    indent = "  " * depth
    chain_icon = "[chain:ok]" if chain.valid else f"[chain:BROKEN at seq {chain.first_broken_sequence}]"
    print(f"{indent}{session_id}  tools={tool_count}  {chain_icon}")
    for child_id in store.children_of(session_id):
        print_tree(store, child_id, depth + 1)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = str(Path(tmpdir) / "multi-agent.sqlite")

        # --- Build sessions ---

        # Orchestrator does some work, then delegates to two worker agents.
        # Passing a tool_response with "session_id" to the Agent tool is what
        # causes hooks.py to emit a session_spawn event linking parent → child.
        simulate_session(store_path, "orchestrator-001", [
            ("Read",  {"file_path": "research-plan.md"}, {"content": "## Research Plan\n1. Search\n2. Summarise"}),
            ("Bash",  {"command": "echo 'dispatching workers'"}, {"output": "dispatching workers", "exit_code": 0}),
            ("Agent", {"description": "search for CHP papers"},     {"session_id": "search-001",    "result": "found 3 papers"}),
            ("Agent", {"description": "summarise the findings"},    {"session_id": "summarise-001", "result": "summary written"}),
        ])

        # Search worker
        simulate_session(store_path, "search-001", [
            ("WebFetch", {"url": "https://example.com/papers/1"}, {"content": "CHP paper abstract..."}),
            ("WebFetch", {"url": "https://example.com/papers/2"}, {"content": "Related work..."}),
            ("Bash",     {"command": "grep -r CHP /tmp/papers"},   {"output": "CHP line 1\nCHP line 2", "exit_code": 0}),
        ])

        # Summarise worker — also spawns a proofreader
        simulate_session(store_path, "summarise-001", [
            ("Read",  {"file_path": "search-001-notes.md"}, {"content": "3 relevant papers found"}),
            ("Edit",  {"file_path": "summary.md"},          {"result": "ok"}),
            ("Agent", {"description": "proofread summary"}, {"session_id": "proofread-001", "result": "approved"}),
        ])

        # Proofreader (depth 2)
        simulate_session(store_path, "proofread-001", [
            ("Read",  {"file_path": "summary.md"}, {"content": "# CHP Summary\n..."}),
            ("Write", {"file_path": "summary.md"}, {"result": "ok"}),
        ])

        # --- Reconstruct and display the tree ---
        store = SQLiteEvidenceStore(store_path)

        print("=== Multi-Agent Session Tree ===\n")
        print_tree(store, "orchestrator-001")

        # --- Show session_spawn events explicitly ---
        print("\n=== session_spawn events on orchestrator-001 ===\n")
        spawn_events = [
            e for e in store.by_correlation("orchestrator-001")
            if e["event_type"] == "session_spawn"
        ]
        for ev in spawn_events:
            print(json.dumps({
                "event_type": ev["event_type"],
                "parent":     ev["payload"]["parent_session_id"],
                "child":      ev["payload"]["child_session_id"],
                "tool":       ev["payload"]["tool_name"],
            }, indent=2))

        # --- CorrelationContext with explicit parent link (programmatic use) ---
        print("\n=== CorrelationContext.parent_correlation_id (programmatic) ===\n")
        root_ctx = CorrelationContext(correlation_id="orchestrator-001")
        child_ctx = CorrelationContext(
            correlation_id="search-001",
            parent_correlation_id="orchestrator-001",
        )
        print(f"  root.correlation_id:          {root_ctx.correlation_id}")
        print(f"  root.parent_correlation_id:   {root_ctx.parent_correlation_id}")
        print(f"  child.correlation_id:         {child_ctx.correlation_id}")
        print(f"  child.parent_correlation_id:  {child_ctx.parent_correlation_id}")

        store.close()
