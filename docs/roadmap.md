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

**v0.3.1 — Agent Session Descriptor + Memory Capability**  
`AgentSessionDescriptor` captures intent, model, autonomy tier, and tool manifest at session start. `MemoryCapability` provides governed key-value memory (get/set/delete/list) with scoped evidence events (`memory_read`, `memory_written`, `memory_deleted`).

**v0.3.2 — Planning + Reflection Event Family**  
`PlanningContext` and `ReflectionContext` make agent reasoning observable. New event family: `plan_created`, `plan_step_started/completed`, `plan_revised`, `reflection_started/completed`, `outcome_scored`. `EvaluationResult` type for structured scoring.

**v0.3.3 — Delegation + Cross-Agent Handoff**  
`DelegationContext` and `DelegationEnvelope` give every agent-to-agent handoff explicit lifecycle evidence. Event family: `delegation_created`, `delegation_accepted`, `delegation_completed`, `delegation_rejected`, `delegation_reassigned`. `chp delegation show` renders the full handoff chain.

**v0.3.4 — Autonomy Profile + Budget Gates**  
`AutonomyProfile` field on `CapabilityDescriptor`: `tier` (`automated` | `supervised` | `approval_required` | `human_driven`), `spend_limit`, `action_limit`, `rollback_policy`. Budget gates block invocations when limits are exceeded and emit `budget_exceeded` / `approval_requested` evidence. `chp session autonomy-report` shows all autonomy decisions for a session.

## Guiding Rule

Local visibility should be free. Production trust should be paid.

## Up Next — v0.3.5

Closes the open loop from v0.3.4. `tier="approval_required"` blocks invocations but has no
resolution path. v0.3.5 adds:

- `host.grant_approval(correlation_id, capability_uri, ...)` — records `approval_granted` event
- `host.deny_approval(correlation_id, capability_uri, ...)` — records `approval_denied` event
- `chp session autonomy-report` updated with `pending_approvals` count and resolved/unresolved classification

## Up Next — v0.4

The v0.4 milestone shifts focus to governed data access. Candidate work items:

- **Retrieval Capability** — `RetrievalCapability` base class for keyword, vector, and hybrid
  search. Source citation (document ID, title, score) recorded in evidence for every retrieval
  call. Every RAG query becomes auditable, replayable, and policy-addressable.
- **Ingestion Capability** — governed data loading with provenance tracking
- **Knowledge Graph Capability** — entity/relationship stores as first-class capabilities
