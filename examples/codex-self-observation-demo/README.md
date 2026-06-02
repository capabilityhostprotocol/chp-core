# Codex Self-Observation Demo

This demo proves the dogfooding loop:

1. Codex records engineering actions as CHP capability invocations.
2. Evidence is emitted locally.
3. The trace is replayed by correlation ID.
4. `explain_execution` explains what happened from evidence.
5. Evidence can be mapped to an OpenTelemetry-like span shape.

Run from the repository root:

```bash
python examples/codex-self-observation-demo/demo.py
```

No cloud service, LLM, MCP server, or OpenTelemetry SDK is required.
