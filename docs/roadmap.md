# CHP Roadmap

> CHP makes capability execution visible, replayable, and ready for governance.

## v0.1 — Local Execution Evidence (shipped)

- Minimal protocol spec and JSON schemas
- Python reference host (`chp-core`) and TypeScript types (`@capabilityhostprotocol/types`)
- Append-only local evidence store, replay by correlation ID
- Conformance suite and examples

## v0.2 — Capability Contracts and Model Adapters

Capability contract extensions and first-class adapters for Claude, OpenAI, and Gemini — wrapping LLM tool calls as evidenced CHP capabilities.

## v0.3+ — Agent-Native Operations

Agent sessions, wrap-tool primitives, tamper-evidence, observability alignment (OpenTelemetry export), and a local capability registry.

## v1.0 — Ecosystem Boundary

**Open source:**
spec · schemas · local host · conformance · contract template · registry seed · maturity model · local replay · OTel export · model adapters · stable MCP adapter

**Commercial / hosted:**
hosted capability graph · multi-host trace stitching · long-term retention · team workspaces · enterprise RBAC · compliance exports · marketplace

## Guiding Rule

Local visibility should be free. Production trust should be paid.
