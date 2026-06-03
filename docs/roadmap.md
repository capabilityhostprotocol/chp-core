# CHP Roadmap

The launch claim stays narrow:

> CHP makes capability execution visible, replayable, and ready for governance.

## v0.1: Local Execution Evidence (current)

Prove a capability can be declared, invoked, evidenced, replayed, and verified locally.

- Minimal protocol spec and JSON schemas
- Python local host (`chp-core` on PyPI)
- TypeScript protocol types (`@capabilityhostprotocol/types` on npm)
- Append-only local evidence store (SQLite, local only)
- Correlation propagation
- Replay by correlation ID
- Outcomes: `success`, `failure`, `denied`, `skipped`
- Agent/tool observability demo
- Experimental MCP bridge prototype
- Conformance suite

## v0.2: Capability Contracts

Convert the protocol's capability concept into concrete developer assets without breaking v0.1 descriptors.

- Capability contract template
- Capability maturity model
- Host conformance levels
- Optional contract extensions: provider, owner, lifecycle metadata, errors, limits, side effects, policy declarations
- `chp validate-contract` CLI command

Acceptance criteria: existing v0.1 descriptors remain valid; contracts are local-first.

## v0.3: Tamper-Evidence

Introduce integrity guarantees for the evidence store.

- Hash chaining: each event carries the hash of the previous event in the same correlation stream
- Host identity key pair: evidence events signed at emission time
- `chp verify-evidence <correlation-id>` CLI
- Signed export bundles for auditors

Unsigned v0.1 events will be treated as legacy and pass a lenient verification mode.

## v0.4: Agent-Native Capability Operations

Make agent/tool execution observable without requiring every tool to be CHP-native.

- Agent session descriptor
- Tool invocation receipt convention
- Plan and reflection evidence conventions
- Local wrapper for ordinary tool calls
- Execution comparison across attempts

## v0.5: Policy, Approval, and Safety Events

Turn governance readiness into explicit protocol objects.

- Policy declaration schema
- Approval event schema
- Authorization decision event schema
- Local approval example
- Audit export format
- Evidence redaction helper

Does not require a full entitlement engine.

## v0.6: Observability Alignment

Integrate with existing operations systems without competing with them.

- OpenTelemetry export adapter
- Capability health/readiness convention
- Metrics naming convention
- Incident evidence convention

## v1.0: Ecosystem Boundary

**Open source:**
- Spec, schemas, conformance suite
- Local host (Python + additional languages)
- Contract template and maturity model
- Registry seed format
- Local replay and local audit
- OpenTelemetry export
- Stable MCP adapter

**Commercial / hosted:**
- Hosted capability graph
- Multi-host trace stitching
- Long-term retention and compliance exports
- Team workspaces and enterprise identity
- Policy administration and certification workflows

## Guiding Rule

Local visibility should be free. Production trust should be paid.
