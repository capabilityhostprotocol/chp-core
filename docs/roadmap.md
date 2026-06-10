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

**v0.3.5 — Approval Resolution**  
Closes the `approval_required` open loop. `host.grant_approval()` and `host.deny_approval()` record `approval_granted` / `approval_denied` evidence events. `chp session autonomy-report` updated with `pending_approvals` count and resolved/unresolved classification.

**v0.4.0 — Retrieval Capability**  
`RetrievalCapability` base class for keyword, vector, and hybrid search. Source citation (document ID, title, score) recorded in hash-chained evidence for every retrieval call. Every RAG query becomes auditable and replayable.

**v0.4.1 — Data Ingestion Capability**  
`DataIngestionCapability` with governed ingest, SHA256 content provenance, and `ingestion_completed` evidence events.

**v0.4.2 — Transformation Capability**  
`TransformationCapability` for normalize/chunk/redact operations. SHA256 provenance links output back to input across every transformation step.

**v0.4.3 — Knowledge Graph Capability**  
Governed entity/relation store with BFS traversal. Every graph mutation emits structured evidence.

**v0.4.4 — Workflow Orchestration + Domain Events**  
Workflow steps as first-class capabilities. Domain event bus with `event_published` / `event_consumed` evidence.

**v0.4.5 — Metrics + Capability Certification**  
Metrics naming convention and `chp certify` CLI. Capabilities can be assessed against a maturity rubric and issued a certification record.

**v0.4.6–v0.4.7 — Approval CLI, Version Control, Identity, Composability**  
`chp approval` subcommands, version control capability exports, identity propagation through delegation chains, composability utilities.

**v0.5.0 — State Machine + Agent Interface**  
`StateMachineCapability` (§6.3) and `AgentInterfaceCapability` (§7.2). State transitions emit structured evidence; agent interfaces expose governed tool manifests.

**v0.5.1 — Safety + Compliance**  
Safety gate capability (§8.5) and compliance check capability (§8.6). Pre-execution safety scoring and policy-aligned compliance assertions with evidence.

**v0.5.2 — Incident Management**  
`IncidentManagementCapability` (§9.5). Structured incident lifecycle: `incident_opened`, `incident_updated`, `incident_resolved` evidence events.

**v0.6.0 — SQLite Persistence Wave**  
All stateful capabilities (memory, knowledge graph, workflow, retrieval, incident) persist to SQLite stores. Evidence and capability state survive process restarts.

**v0.6.1 — Adopter Experience**  
`chp host verify` — smoke-tests a host and evidence store end-to-end. `chp serve-http` — exposes any `LocalCapabilityHost` over HTTP with a single command. `docs/adopter-quickstart.md` revised.

**v0.6.2 — Vector Retrieval**  
Cosine-similarity vector search using only stdlib (`array`, `math`). No numpy, no external deps. Plugs into `RetrievalCapability` as a scored backend.

**v0.6.3 — RemoteCapabilityHost**  
Cross-host invocation over HTTP. A host can invoke capabilities on another CHP host running `chp serve-http`. Correlation IDs, evidence, and denial codes propagate across the boundary.

## Guiding Rule

Local visibility should be free. Production trust should be paid.

## Current — v0.6.3

The protocol is stable and public. Focus shifts to adoption: third-party implementors, external language SDKs, and production deployments.

## Up Next — v0.7

Candidate work items for the v0.7 wave:

- **Redaction policies** — `chp.redact_evidence_payload` capability; per-capability redaction rules stored in `.chp/policy.json`
- **Catalog alignment tooling** — `chp.check_catalog_alignment` to verify roadmap, contracts, and examples against the registered capability catalog
- **Capability contract validation** — `chp.validate_capability_contract` against the canonical contract template
- **Maturity assessment** — `chp.assess_capability_maturity` scores capabilities against the L1–L7 maturity ladder
- **Cross-run comparison** — `chp.compare_runs` diffs two work traces for regressions and improvements
