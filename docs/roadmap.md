# CHP Roadmap

> CHP makes capability execution visible, replayable, and ready for governance.

## Shipped

**v0.1 — Local Execution Evidence**  
Minimal protocol spec, JSON schemas, Python reference host (`chp-core`), TypeScript types (`@capabilityhostprotocol/types`), append-only SQLite evidence store, replay by correlation ID, conformance suite.

**v0.2.0 — Model Adapters**  
First-class adapters for Claude, OpenAI, and Gemini. Every LLM call becomes a governed, replayable CHP capability. `chp validate-contract` CLI.

**v0.2.1 — Agentic Emission**  
Zero-config evidence from Claude Code sessions. `chp hooks install` → every tool call and session stored automatically. No application code changes required.

## Active — v0.2 Series

The v0.2 series focuses on making agentic development fully observable by default. Upcoming patches (no dates, no promises):

- **Session intelligence** — pre-tool governance hooks, session export, richer session view
- **Multi-agent correlation** — parent-child session trees when agents spawn agents
- **More agent adapters** — Codex, Gemini CLI, others following the same hook pattern
- **Programmatic wrapping** — `AgentSession` context manager, `wrap_tool_call()` one-shot wrapper
- **Evidence integrity** — hash chaining, portable signed bundles, `chp verify-evidence`
- **Policy gates** — pre-tool invariant enforcement, risk tiers, approval events
- **Observability alignment** — OpenTelemetry export, capability health endpoints
- **Local registry** — `~/.chp/registry.yaml`, maturity assessment, `chp registry`

## Guiding Rule

Local visibility should be free. Production trust should be paid.
