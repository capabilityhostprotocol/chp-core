"""Evidence querying, discovery, and policy gates demo (v0.2.7–v0.2.9).

Story: "Governing a mixed-risk tool fleet."

Four capabilities spanning all risk/status combinations are registered and
invoked (one intentionally fails). The demo then walks through every querying
surface, discovery dimension, and the BlockPattern regex policy gate —
including audit_only mode where a dangerous invocation is observed but not
blocked.

APIs demonstrated:
- store.query() with all keyword filters: capability_id, outcome, since, until, limit
- host.query_evidence() and host.evidence_count()
- ReplayQuery(correlation_id, since_sequence, limit, include_payloads=False)
- host.replay_result(query)
- host.discover() with namespace, tags, risk, status filters
- PolicyConfig(block_patterns=[BlockPattern(...)]) — regex block on payload field
- PolicyConfig(audit_only=True) — match observed, execution not blocked
- wrap_tool_call(..., policy=...) — policy evaluated before fn() runs

Run:
    PYTHONPATH=packages/python python examples/evidence-query-and-policy-demo/demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from chp_core import LocalCapabilityHost, ReplayQuery, SQLiteEvidenceStore, capability, wrap_tool_call
from chp_core.policy import BlockPattern, PolicyConfig


# ── Capability handlers ──────────────────────────────────────────────────────

@capability(
    id="files.read",
    version="1.0.0",
    description="Read a file by path.",
    risk="low",
    status="certified",
    tags=["read", "files"],
)
def read_file(ctx, payload):
    return {"content": f"content of {payload['path']}"}


@capability(
    id="files.write",
    version="1.0.0",
    description="Write content to a file.",
    risk="medium",
    status="certified",
    tags=["write", "files"],
)
def write_file(ctx, payload):
    return {"written": True, "path": payload["path"]}


@capability(
    id="shell.run",
    version="1.0.0",
    description="Execute a shell command.",
    risk="high",
    status="experimental",
    tags=["execute", "shell"],
)
def run_shell(ctx, payload):
    return {"stdout": f"ran: {payload['command']}", "exit_code": 0}


@capability(
    id="net.fetch",
    version="1.0.0",
    description="Fetch a URL.",
    risk="low",
    status="draft",
    tags=["read", "network"],
)
def fetch_url(ctx, payload):
    url = payload["url"]
    if url.startswith("bad://"):
        raise ValueError(f"Invalid URL scheme: {url}")
    return {"status": 200, "body": f"fetched {url}"}


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = str(Path(tmpdir) / "demo.sqlite")
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("fleet-host", store=store)

        for fn in (read_file, write_file, run_shell, fetch_url):
            host.register(fn)

        corr = "fleet-demo"

        host.invoke("files.read",  {"path": "/etc/hosts"},                       correlation_id=corr)
        host.invoke("files.write", {"path": "/tmp/out.txt", "content": "hello"}, correlation_id=corr)
        host.invoke("shell.run",   {"command": "ls /tmp"},                       correlation_id=corr)
        host.invoke("net.fetch",   {"url": "https://example.com"},               correlation_id=corr)
        host.invoke("net.fetch",   {"url": "bad://invalid"},                     correlation_id=corr)

        # --- Discovery ---
        print("=== Discovery ===\n")
        ns_files  = host.discover(namespace="files.")
        t_read    = host.discover(tags=["read"])
        r_high    = host.discover(risk="high")
        s_draft   = host.discover(status="draft")

        print(f"  namespace='files.': {[c['id'] for c in ns_files['capabilities']]}")
        print(f"  tags=['read']:       {[c['id'] for c in t_read['capabilities']]}")
        print(f"  risk='high':         {[c['id'] for c in r_high['capabilities']]}")
        print(f"  status='draft':      {[c['id'] for c in s_draft['capabilities']]}")

        # --- store.query() ---
        print("\n=== store.query() ===\n")
        by_cap   = store.query(capability_id="files.read")
        failures = store.query(outcome="failure")
        first_3  = store.query(limit=3)

        print(f"  capability_id='files.read': {len(by_cap)} events")
        print(f"  outcome='failure':          {len(failures)} events  → caps: {[e.get('capability_id') for e in failures]}")
        print(f"  limit=3:                    {len(first_3)} events")

        # --- host.query_evidence() + evidence_count() ---
        print("\n=== host.query_evidence() + evidence_count() ===\n")
        shell_ev = host.query_evidence(capability_id="shell.run")
        all_ev   = host.query_evidence()
        total    = host.evidence_count(corr)

        print(f"  shell.run events: {len(shell_ev)}")
        print(f"  all events:       {len(all_ev)}")
        print(f"  total in corr:    {total}")

        # --- ReplayQuery pagination ---
        print("\n=== ReplayQuery (since_sequence=2, limit=4, include_payloads=False) ===\n")
        rq     = ReplayQuery(correlation_id=corr, since_sequence=2, limit=4, include_payloads=False)
        replay = host.replay_result(rq)

        print(f"  replayed {replay.event_count} event(s):")
        for ev in replay.events:
            print(f"    seq={ev.get('sequence')}  type={ev.get('event_type')}  cap={ev.get('capability_id')}")

        # --- BlockPattern: deny rm -rf ---
        print("\n=== BlockPattern: deny rm -rf ===\n")
        danger_policy = PolicyConfig(
            block_patterns=[
                BlockPattern(
                    capability_id="claude_code.bash",
                    field="command",
                    pattern=r"rm\s+-rf",
                    reason="Unscoped deletion prohibited by policy",
                )
            ]
        )

        try:
            wrap_tool_call(
                "Bash",
                {"command": "rm -rf /tmp/scratch"},
                fn=lambda inp: {"exit_code": 0},
                store_path=store_path,
                policy=danger_policy,
            )
            print("  rm -rf: not blocked (unexpected)")
        except RuntimeError as exc:
            print(f"  rm -rf: blocked  → {exc}")

        safe = wrap_tool_call(
            "Bash",
            {"command": "ls /tmp"},
            fn=lambda inp: {"stdout": "file1.txt\n", "exit_code": 0},
            store_path=store_path,
            policy=danger_policy,
        )
        print(f"  ls /tmp: allowed → exit_code={safe['exit_code']}")

        # --- audit_only: match observed, execution not blocked ---
        print("\n=== audit_only=True: match observed, execution proceeds ===\n")
        audit_policy = PolicyConfig(
            block_patterns=[
                BlockPattern(
                    capability_id="claude_code.bash",
                    field="command",
                    pattern=r"rm\s+-rf",
                    reason="Unscoped deletion (audit)",
                )
            ],
            audit_only=True,
        )

        result = wrap_tool_call(
            "Bash",
            {"command": "rm -rf /tmp/scratch"},
            fn=lambda inp: {"exit_code": 0, "deleted": True},
            store_path=store_path,
            policy=audit_policy,
        )
        print(f"  rm -rf with audit_only: result={result}")
        print("  (pattern matched and recorded in evidence — execution was not blocked)")
