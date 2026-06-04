# CHP Roadmap

> CHP makes capability execution visible, replayable, and ready for governance.

## Shipped

**v0.1 — Local Execution Evidence**  
Minimal protocol spec, JSON schemas, Python reference host (`chp-core`), TypeScript types (`@capabilityhostprotocol/types`), append-only SQLite evidence store, replay by correlation ID, conformance suite.

**v0.2.0 — Model Adapters**  
First-class adapters for Claude, OpenAI, and Gemini. Every LLM call becomes a governed, replayable CHP capability. `chp validate-contract` CLI.

**v0.2.1 — Agentic Emission**  
Zero-config evidence from Claude Code sessions. `chp hooks install` → every tool call and session stored automatically. No application code changes required.

**v0.2.2 — Session Intelligence**  
Pre-tool governance hooks, session export (`chp session export`), richer session view (`chp session show`), structured session summaries.

**v0.2.3 — Multi-Agent Correlation**  
Parent-child session trees when agents spawn agents. `chp session tree` visualises the full call graph. Correlation propagation across agent boundaries.

**v0.2.4 — More Agent Adapters**  
Codex CLI and Gemini CLI adapters follow the same hook pattern as Claude Code. `chp hook codex-post-tool`, `chp hook gemini-post-tool`, and matching stop hooks.

**v0.2.5 — Programmatic Wrapping**  
`AgentSession` context manager and `wrap_tool_call()` one-shot wrapper. Record CHP evidence without Claude Code hooks — useful for tests, scripts, and non-interactive agents.

**v0.2.6 — Evidence Integrity**  
SHA256 hash chaining across every evidence event. `chp verify-evidence <session_id>` walks the chain and reports tampering. `chp session export` bundles include `chain_valid`.

**v0.2.7 — Policy Gates**  
Pre-tool invariant enforcement extended with risk tiers (`max_risk_tier`), audit-only mode (`audit_only`), and capability allowlists. `CAPABILITY_RISK_MAP` covers all built-in adapters.

**v0.2.8 — Observability Alignment**  
OpenTelemetry export via `chp session otel`. `export_otlp_http` ships spans to any OTLP collector using only stdlib. `/health` endpoint on the HTTP host.

**v0.2.9 — Local Registry**  
`~/.chp/registry.json` tracks enabled adapters. `chp registry list/add/remove/status` provides discovery and maturity assessment without extra dependencies.

## Guiding Rule

Local visibility should be free. Production trust should be paid.

## Up Next — v0.3

The v0.3 milestone shifts from local visibility to shared trust. Candidate work items:

- **Signed bundles** — cryptographic signing of session exports (ed25519); `chp verify-bundle`
- **Remote store** — optional push/pull to a shared evidence endpoint; enables team-wide replay
- **Policy-as-code** — version-controlled `.chp/policy.toml` with structured rules and a linter
- **CI integration** — `chp ci check` as a gate in GitHub Actions; fails the build on policy violations
- **SDK ergonomics** — typed decorator `@chp.capability` for Python; auto-generates the descriptor
