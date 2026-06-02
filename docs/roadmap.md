# CHP Roadmap

This roadmap is now aligned with the broader capability taxonomy in
`docs/CHP_Capability_Catalog.md`. The detailed catalog conversion lives at
`docs/capabilities/catalog-roadmap.md`.

The launch claim stays narrow:

> CHP makes capability execution visible, replayable, and ready for governance.

## v0.1: Local Execution Evidence

Goal: prove a capability can be declared, invoked, evidenced, replayed, and
compared locally.

Ship:

- minimal protocol spec
- JSON schemas
- Python local host
- append-only local evidence store
- correlation propagation
- replay by correlation ID
- outcomes: `success`, `failure`, `denied`, `skipped`
- first three capabilities: `trace_execution`, `explain_execution`,
  `evaluate_counterfactual`
- Codex/work evidence controls
- agent/tool observability demo
- experimental MCP bridge prototype
- conformance suite

Do not add marketplace, billing, enterprise RBAC, distributed scheduling, or
hosted capability graph requirements to v0.1.

## v0.2: Capability Contracts and Registry Seed

Goal: convert the catalog's capability contract template into concrete open
source developer assets without breaking v0.1 descriptors.

Planned:

- capability contract template
- capability maturity model
- host conformance levels
- capability registry seed
- optional contract extensions for:
  - provider
  - owner
  - status
  - errors
  - limits
  - side effects
  - host requirements
  - policy declarations
  - observability declarations
  - lifecycle metadata
- `chp.validate_capability_contract`
- `chp.assess_capability_maturity`
- `chp.check_catalog_alignment`

Acceptance criteria:

- existing v0.1 descriptors remain valid
- extended contracts are local-first
- registry seed can list local and example capabilities
- catalog alignment can be checked through CHP evidence

## v0.3: CHP Builds CHP

Goal: make CHP useful to the team building CHP through real development
evidence.

Implemented:

- `chp.inventory_agentic_capabilities`
- `chp.audit_evidence_quality`
- `chp.run_conformance_matrix`
- `chp.version_control.inspect_repo`
- `chp.version_control.diff_summary`
- `chp.version_control.precommit_check`
- `chp.version_control.release_evidence_bundle`
- `chp.version_control.verify_merge_readiness`
- lightweight capability adapter layer
- experimental Radicle identity and patch controls

Next:

1. `chp.wrap_tool_call`
2. `chp.compare_runs`
3. `chp.propose_next_issue`
4. `chp.check_catalog_alignment`
5. Radicle release-bundle comment integration

The maintained inventory lives at
`docs/capabilities/agentic-development-inventory.md` and can be generated as
evidence with `chp work inventory`.

Version-control governance lives at
`docs/capabilities/version-control-governance.md` and starts with local Git
evidence plus guarded experimental Radicle controls.

Adapter architecture lives at `docs/design/capability-adapter-layer.md`; the
core primitive is intentionally small so future MCP, Radicle, catalog, and
agent-tool adapters can be added without changing the host protocol.

## v0.4: Agent-Native Capability Operations

Goal: make agent/tool execution observable without requiring every tool to be
CHP-native.

Planned:

- agent session descriptor proposal
- tool invocation receipt convention
- plan and reflection evidence conventions
- autonomy control design note
- local wrapper for ordinary tool calls
- comparison of traces across attempts
- issue proposal from failed checks and repeated manual work

## v0.5: Host Requirement Declarations

Goal: represent substrate needs from the catalog before building any substrate
runtime.

Planned host requirement descriptors:

- compute
- storage
- inference
- runtime
- isolation
- networking
- locality

Acceptance criteria:

- requirements are discoverable
- no scheduler is required
- no cloud service is required
- capability authors can declare what a capability needs to run safely

## v0.6: Policy, Approval, Audit, and Safety Events

Goal: turn governance readiness into explicit protocol objects and event
semantics.

Planned:

- policy declaration schema
- approval event schema
- authorization decision event schema
- safety/risk tier profile
- local approval example
- audit export format
- evidence redaction helper

Do not require a full entitlement engine in this phase.

## v0.7: Observability and Operations Alignment

Goal: integrate with existing operations systems without competing with them.

Planned:

- OpenTelemetry export adapter
- capability health/readiness convention
- metrics naming convention
- incident evidence convention
- hash-chained evidence option
- signed evidence bundles
- verification CLI

## v0.8: Domain Capability Maps

Goal: demonstrate practical composition using the catalog's domain capability
families.

Planned:

- engineering capability map
- knowledge work capability map
- first product composition example
- domain examples that inherit the same contract and evidence expectations

## v1.0: Ecosystem Boundary

Open source should include:

- spec
- schemas
- local host
- conformance suite
- contract template
- registry seed format
- maturity model
- local replay
- local audit
- OpenTelemetry export
- stable MCP adapter, if ready

Commercial or hosted value should include:

- hosted capability graph
- multi-host trace stitching
- long-term retention
- team workspaces
- enterprise identity and RBAC
- policy administration
- compliance exports
- signed evidence custody
- marketplace operations
- billing and metering
- certification workflows
- managed capability hosting

## Guiding Rule

Local visibility should be free. Production trust should be paid.
