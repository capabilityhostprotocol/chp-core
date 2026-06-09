# Capability Host Protocol v0.1

Status: draft for open-source launch

CHP v0.1 defines the smallest interoperable surface for governed execution at a capability boundary. It is language-agnostic, transport-agnostic, local-first, embeddable, and useful with one host.

## 1. Purpose

The Capability Host Protocol exists to make execution observable, replayable, and progressively governable at the boundary where an action is invoked.

CHP v0.1 focuses on local execution evidence. A compatible host can declare capabilities, expose discovery, accept invocation envelopes, preserve correlation, emit evidence for every execution attempt, and replay evidence by correlation ID.

The launch value proposition is:

> See what your agents, tools, and systems actually did.

## 2. Definitions

Capability: A discrete executable action with stable identity, version, supported modes, declared invariants, an invocation boundary, and evidence emission.

Capability Host: A runtime that hosts capabilities and participates in CHP. A host may be a process, service, CLI, agent runtime, MCP wrapper, API adapter, device, or business system.

Invocation Envelope: The protocol object used to request capability execution.

Evidence Event: A structured record of execution truth emitted by a host. Evidence is not a free-form log line.

Correlation Context: The causal context carried by invocations and evidence events. It links related execution attempts.

Replay Query: A query object that asks the host to return evidence for a correlation ID.

Replay Result: The ordered evidence returned for a replay query.

Invariant: A declared constraint that describes what should hold before, during, or after execution. v0.1 supports declaration and basic host-denial semantics but does not require a rich policy engine.

Assurance Metadata: Minimal metadata describing the strength and policy of evidence emitted by a host.

Canonical v0.1 protocol object names:

- `CapabilityDescriptor`
- `HostDescriptor`
- `InvocationEnvelope`
- `InvocationResult`
- `ExecutionEvidence`
- `CorrelationContext`
- `ReplayQuery`
- `ReplayResult`

## 3. Capability Descriptor

A capability descriptor declares what action exists and how it may be invoked.

Required fields:

- `id`: stable capability identity, such as `tool.add` or `trace_execution`
- `version`: capability version
- `description`: human-readable purpose
- `modes`: supported invocation modes, at minimum `sync`
- `emits`: evidence event types the capability may emit

Recommended fields:

- `input_schema`: JSON Schema for invocation payloads
- `output_schema`: JSON Schema for successful result data
- `invariants`: declared constraints
- `risk`: `low`, `medium`, `high`, or `critical`
- `assurance`: minimal assurance metadata
- `owner`, `tags`, `metadata`

The stable capability URI is `id:version`.

Schema: `schemas/capability-descriptor.schema.json`

## 4. Host Descriptor

A host descriptor declares the host identity, protocol version, hosted capabilities, and evidence behavior.

Required fields:

- `id`: stable host identity
- `version`: host implementation version
- `protocol_version`: `0.1`
- `kind`: host kind, such as `local`, `service`, `mcp-wrapper`, `cli`, or `device`
- `capabilities`: capability descriptors
- `evidence`: evidence store metadata including whether the store is append-only

Schema: `schemas/host-descriptor.schema.json`

## 5. Invocation Envelope

Every invocation MUST pass through an envelope-compatible boundary.

Required fields:

- `invocation_id`
- `capability_id`
- `mode`
- `correlation`
- `subject`
- `payload`
- `requested_at`

If a caller supplies a correlation ID, the host MUST preserve it. If no correlation ID is supplied, the host MUST generate one and return it in the result and evidence.

Hosts SHOULD NOT copy raw invocation payloads into evidence by default. Capabilities may emit explicit redacted evidence payloads.

A host SHOULD validate `payload` against the capability's `input_schema` when present. Validation failures MUST produce an `execution_denied` outcome with denial code `input_schema_validation_failed` and MUST NOT invoke the capability handler.

If a capability URI (`id:version`) is registered more than once on the same host, the host MUST either raise an error or emit a warning. Silent overwrites are NOT RECOMMENDED.

Schema: `schemas/invocation-envelope.schema.json`

## 6. Execution Evidence Schema

Every execution attempt MUST emit evidence.

Core event types:

- `execution_started`
- `execution_completed`
- `execution_failed`
- `execution_denied`
- `execution_skipped`

Capability-specific event types are allowed when they are structured and correlated. For example, the reference `trace_execution` capability emits `execution_observed`.

Required fields:

- `event_id`
- `event_type`
- `invocation_id`
- `capability_id`
- `host_id`
- `correlation`
- `timestamp`
- `sequence`
- `payload`
- `redacted`
- `assurance`

Evidence MUST be stored append-only. Hosts MUST NOT modify or delete evidence events after they are written. v0.1 does not require cryptographic tamper evidence, remote notarization, or consensus.

Schemas:

- `schemas/execution-evidence.schema.json`
- `schemas/evidence-event.schema.json`

## 7. Correlation Requirements

Hosts MUST:

- preserve caller-provided `correlation.correlation_id`
- generate a correlation ID when missing
- include correlation context in every evidence event
- return correlation context in every invocation result
- support replay by correlation ID

Hosts MUST NOT silently overwrite a caller-provided correlation ID.

Schema: `schemas/correlation-context.schema.json`

## 8. Outcome Semantics

An invocation result outcome is one of:

- `success`: the capability handler completed and returned data
- `failure`: execution began but failed
- `denied`: the host rejected execution before the capability handler completed
- `skipped`: the host intentionally did not execute a registered capability, for example because it is disabled

`success` MUST be true only when `outcome` is `success`.

Successful invocations MUST emit `execution_started` and `execution_completed`.

Failed invocations MUST emit `execution_started` and `execution_failed`.

Denied invocations MUST emit `execution_denied`. Denial may occur before `execution_started`.

Skipped invocations MUST emit `execution_skipped`.

Schema: `schemas/invocation-result.schema.json`

## 9. Error And Denial Semantics

Errors describe execution failures after the boundary admits the invocation.

Denials describe boundary decisions that prevent execution, such as:

- capability not found
- unsupported mode
- capability disabled
- invariant failed
- entitlement denied, where implemented

Denial records SHOULD include:

- stable `code`
- human-readable `message`
- optional `invariant_id`
- `retryable`
- structured `details`

**Standard denial codes.** Implementations SHOULD use these stable codes when applicable:

| Code | When |
|---|---|
| `capability_not_found` | No capability registered at the requested URI |
| `capability_disabled` | Capability exists but is disabled |
| `unsupported_mode` | Requested `mode` not in `modes` |
| `invariant_failed` | A declared invariant rejected the invocation |
| `input_schema_validation_failed` | Payload failed `input_schema` validation |
| `policy_block_pattern_matched` | A policy block pattern matched the payload |
| `risk_tier_exceeded` | Payload risk tier above configured maximum |
| `entitlement_denied` | Caller lacks required entitlement |

v0.1 does not require a complete entitlement system. A host may deny based on local rules or invariants.

## 10. Replay Semantics

Hosts MUST support replay by correlation ID.

A replay query contains:

- `correlation_id`
- optional `limit`
- optional `since_sequence`
- optional `include_payloads`

A replay result contains:

- `correlation_id`
- ordered `events`
- `event_count`
- `replayed_at`

Replay ordering is by local evidence sequence. v0.1 does not define cross-host total ordering.

Hosts SHOULD enforce a maximum `limit` (RECOMMENDED cap: 10,000 events). Clients requesting an unbounded replay MAY receive a bounded result; the `event_count` field reflects the actual count returned.

Schemas:

- `schemas/replay-query.schema.json`
- `schemas/replay-result.schema.json`

## 11. Conformance Requirements

A CHP v0.1 compatible host MUST demonstrate:

1. Capability declaration
2. Capability discovery
3. Invocation through an envelope-compatible boundary
4. Correlation propagation
5. Evidence emission on success
6. Evidence emission on failure
7. Evidence emission on denial or unsupported action
8. Replay by correlation ID
9. Representation of skipped execution, where the host supports disabled or skipped capabilities

The reference conformance runner lives in `conformance/`.

## 12. Non-Goals

CHP v0.1 does not define:

- distributed host discovery
- a required network transport
- a workflow language
- an agent framework
- a complete policy engine
- enterprise RBAC
- hosted retention
- cryptographic proof of evidence integrity
- a replacement for MCP, OpenTelemetry, Temporal, Kafka, or API gateways

These systems can integrate with CHP, but CHP v0.1 stays focused on the capability execution boundary.

## 13. Versioning Strategy

The protocol version for this draft is `0.1`.

Patch-level implementation changes may occur without changing the protocol version if schemas and conformance requirements remain compatible.

Breaking schema or semantic changes require a new protocol version. Until v1.0, breaking changes may occur, but they should be documented with migration notes and conformance updates.

Capability versions are independent of protocol versions. A capability descriptor version identifies the action contract, not the CHP protocol revision.

Conformance runners SHOULD tag results with the `protocol_version` they validated against. A conformance pass is valid only for the protocol version under which it was run.
