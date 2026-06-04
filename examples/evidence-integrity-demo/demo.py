"""Evidence integrity demo (v0.2.6 + v0.2.7).

Shows SHA256 hash chaining, verify_chain(), and policy gates (audit-only,
risk tiers, allowlist).

Run:
    python examples/evidence-integrity-demo/demo.py
"""

import json
import tempfile
from pathlib import Path

from chp_core import AgentSession
from chp_core.policy import BlockPattern, PolicyConfig
from chp_core.session import wrap_tool_call
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Example 1: Hash chain verification
# ---------------------------------------------------------------------------

def example_verify_chain(store_path: str) -> None:
    print("=== Example 1: verify_chain ===")
    session_id = "integrity-demo"

    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "ls"}, {"output": ".", "exit_code": 0})
        session.record_tool("Read", {"file_path": "README.md"}, {"content": "..."})
        session.record_tool("Bash", {"command": "git status"}, {"output": "...", "exit_code": 0})

    store = SQLiteEvidenceStore(store_path)
    result = store.verify_chain(session_id)
    store.close()

    print(f"  event_count:      {result.event_count}")
    print(f"  verified_count:   {result.verified_count}")
    print(f"  unverified_count: {result.unverified_count}")
    print(f"  valid:            {result.valid}")
    print(f"  first_broken_seq: {result.first_broken_sequence}")


# ---------------------------------------------------------------------------
# Example 2: Tamper detection
# ---------------------------------------------------------------------------

def example_tamper_detection(store_path: str) -> None:
    import sqlite3
    print("\n=== Example 2: Tamper detection ===")
    session_id = "tamper-demo"

    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool("Bash", {"command": "echo 'legit'"}, {"output": "legit", "exit_code": 0})
        session.record_tool("Bash", {"command": "echo 'also legit'"}, {"output": "also legit", "exit_code": 0})

    # Simulate tampering: alter event_json of first event
    conn = sqlite3.connect(store_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT sequence FROM evidence_events WHERE correlation_id = ? ORDER BY sequence ASC",
        (session_id,),
    ).fetchall()
    first_seq = rows[0]["sequence"]
    conn.execute(
        "UPDATE evidence_events SET event_json = ? WHERE sequence = ?",
        ('{"tampered": true}', first_seq),
    )
    conn.commit()
    conn.close()

    store = SQLiteEvidenceStore(store_path)
    result = store.verify_chain(session_id)
    store.close()

    print(f"  valid:              {result.valid}  (False = tampering detected)")
    print(f"  first_broken_seq:   {result.first_broken_sequence}")


# ---------------------------------------------------------------------------
# Example 3: Policy gates — audit-only mode
# ---------------------------------------------------------------------------

def example_audit_only(store_path: str) -> None:
    print("\n=== Example 3: Policy gates — audit-only ===")
    session_id = "audit-only-demo"

    policy = PolicyConfig(
        block_capability_ids=["claude_code.bash"],
        audit_only=True,  # observe but NEVER block
    )

    # This would normally be blocked by block_capability_ids,
    # but audit_only=True lets it through while still recording evidence.
    result = wrap_tool_call(
        "Bash",
        {"command": "echo 'audit mode'"},
        fn=lambda inp: {"output": "audit mode", "exit_code": 0},
        store_path=store_path,
        session_id=session_id,
        policy=policy,
    )
    print(f"  result: {result}")

    store = SQLiteEvidenceStore(store_path)
    events = store.by_correlation(session_id)
    store.close()
    requested = [e for e in events if e["event_type"] == "tool_use_requested"]
    print(f"  evidence recorded: {len(events)} events")
    print(f"  pre-tool outcome: {requested[0]['outcome'] if requested else 'n/a'} (success even though pattern matched)")


# ---------------------------------------------------------------------------
# Example 4: Risk tier blocking
# ---------------------------------------------------------------------------

def example_risk_tier_block(store_path: str) -> None:
    print("\n=== Example 4: Risk tier blocking ===")
    policy = PolicyConfig(max_risk_tier="low")  # only allow low-risk caps

    try:
        wrap_tool_call(
            "Bash",
            {"command": "ls"},
            fn=lambda inp: {},
            store_path=store_path,
            session_id="risk-tier-demo",
            policy=policy,
        )
    except RuntimeError as exc:
        print(f"  Blocked: {exc}")


# ---------------------------------------------------------------------------
# Run all examples
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = str(Path(tmpdir) / "demo.sqlite")
        example_verify_chain(store_path)
        example_tamper_detection(store_path)
        example_audit_only(store_path)
        example_risk_tier_block(store_path)
