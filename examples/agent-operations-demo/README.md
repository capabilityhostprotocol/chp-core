# Agent Operations Demo

This demo shows the open-source wedge for CHP v0.1:

1. A user asks a simple local agent to perform a task.
2. The agent chooses local tools.
3. Tool calls are invoked through a CHP host.
4. Structured evidence is emitted.
5. The trace is replayed by correlation ID.
6. A rules-based explanation is generated.
7. A counterfactual invariant shows what could have been constrained.

Run from the repository root:

```bash
python examples/agent-operations-demo/demo.py
```

The demo uses an in-memory SQLite evidence store and has no network or LLM
dependency.

See `sample-output.txt` for representative terminal output.
