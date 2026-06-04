"""AgentSession and wrap_tool_call demo (v0.2.5).

Shows how to record CHP evidence from arbitrary Python code without
needing Claude Code hooks. Useful for wrapping scripts, pipelines, or
any tool-calling code you own.

Run:
    python examples/agent-session-demo/demo.py
"""

import json
import subprocess
import tempfile
from pathlib import Path

from chp_core import AgentSession, wrap_tool_call
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Example 1: AgentSession context manager
# ---------------------------------------------------------------------------

def run_ls(inp: dict) -> dict:
    """A simple tool function that lists a directory."""
    result = subprocess.run(
        ["ls", inp.get("path", ".")],
        capture_output=True,
        text=True,
    )
    return {"output": result.stdout, "exit_code": result.returncode}


def example_agent_session(store_path: str) -> None:
    print("=== Example 1: AgentSession ===")
    session_id = "demo-agent-session"

    with AgentSession(store_path=store_path, session_id=session_id) as session:
        # record_tool: you supply both input and response (observation-only)
        session.record_tool(
            "Read",
            {"file_path": "README.md"},
            {"content": "(README contents)", "exit_code": 0},
        )

        # wrap: session calls the function and records outcome automatically
        result = session.wrap("Bash", {"path": "."}, run_ls)
        print(f"  ls result: {result['output'][:40].strip()!r}...")

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()

    print(f"  {len(events)} events recorded:")
    for e in events:
        print(f"    [{e['event_type']:24s}]  cap={e['capability_id']}  outcome={e.get('outcome') or '-'}")


# ---------------------------------------------------------------------------
# Example 2: wrap_tool_call one-shot
# ---------------------------------------------------------------------------

def example_wrap_tool_call(store_path: str) -> None:
    print("\n=== Example 2: wrap_tool_call (one-shot) ===")
    session_id = "demo-wrap-call"

    result = wrap_tool_call(
        "Bash",
        {"command": "echo 'hello from CHP'"},
        fn=lambda inp: subprocess.run(
            inp["command"], shell=True, capture_output=True, text=True,
            check=False,
        ),
        store_path=store_path,
        session_id=session_id,
    )
    print(f"  stdout: {result.stdout.strip()!r}")

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()

    print(f"  {len(events)} events (pre-tool + post-tool):")
    for e in events:
        print(f"    [{e['event_type']:24s}]  outcome={e.get('outcome') or '-'}")


# ---------------------------------------------------------------------------
# Example 3: wrap_tool_call with policy block
# ---------------------------------------------------------------------------

def example_policy_block(store_path: str) -> None:
    from chp_core.policy import PolicyConfig
    print("\n=== Example 3: Policy block via wrap_tool_call ===")

    policy = PolicyConfig(block_capability_ids=["claude_code.bash"])
    try:
        wrap_tool_call(
            "Bash",
            {"command": "rm -rf /"},
            fn=lambda inp: {},
            store_path=store_path,
            session_id="demo-blocked",
            policy=policy,
        )
    except RuntimeError as exc:
        print(f"  Blocked as expected: {exc}")


# ---------------------------------------------------------------------------
# Run all examples
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = str(Path(tmpdir) / "demo.sqlite")
        example_agent_session(store_path)
        example_wrap_tool_call(store_path)
        example_policy_block(store_path)
