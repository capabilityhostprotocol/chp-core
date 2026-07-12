# CHP v0.1 Threat Model

> **Superseded (2026-07-12) by [spec/chp-security-model.md](../../spec/chp-security-model.md)**
> — the normative, cross-version properties matrix (guarantee × adversary ×
> residual-risk). Every Non-Goal below (tamper-evident ledgers, host attestation,
> policy evaluation, multi-host causal ordering) has since **shipped** in v0.2+
> (witnessing/anchoring/Merkle head, attestation + anchors, the governed pipeline
> + mandates, `chp-causal-order-v1`). This v0.1 document is kept for history; the
> security model is now maintained in the spec.

## Scope

This threat model covers CHP v0.1 local hosts, schemas, local evidence stores, examples, and conformance. It does not cover hosted multi-tenant services or production SaaS controls.

## Assets

- Capability descriptors
- Invocation envelopes
- Correlation IDs
- Evidence events
- Local evidence store files
- Subject metadata
- Capability input and output data

## Trust Boundaries

- Caller to capability host
- Capability handler to evidence store
- Host process to local filesystem
- Optional bridge surfaces, such as MCP-like tools or agent loops

## Threats And Mitigations

Tampering with evidence:

- v0.1 requires append-only store behavior.
- The reference SQLite store inserts evidence events and never replaces existing events.
- This is not tamper-proof. Cryptographic sealing is deferred.

Correlation loss or overwrite:

- Hosts must preserve caller-supplied correlation IDs.
- Hosts must generate IDs only when missing.
- Evidence and results must include the final correlation context.

Sensitive input leakage:

- Hosts should not copy raw invocation payloads into evidence by default.
- The reference host records capability URI and explicit redacted handler emissions.
- Examples avoid secrets and external credentials.

Hidden failures or denials:

- Failed executions must emit `execution_failed`.
- Denied executions must emit `execution_denied`.
- Unsupported capability and unsupported mode are denial cases.

Misleading evidence:

- Evidence contains `host_id`, `invocation_id`, `capability_id`, timestamp, sequence, and correlation.
- v0.1 does not prove that a host is honest. It only standardizes the structure a host must emit.

Replay confusion:

- Replay is scoped by correlation ID and ordered by local append sequence.
- Cross-host ordering is not guaranteed in v0.1.

Bridge abuse:

- MCP-style or agent tool bridges must validate inputs and avoid blindly trusting tool descriptions.
- Bridge packages should preserve CHP evidence even when the bridged protocol has different error semantics.

## Non-Goals

- Tamper-evident ledgers
- Remote attestation
- Enterprise identity and RBAC
- Long-term retention policy
- Full policy evaluation
- Secrets scanning
- Multi-host causal total ordering

## Required Launch Checks

- Evidence store uses append-only writes.
- Correlation IDs are preserved in tests.
- Failure and denial events are covered by conformance.
- Demo payloads do not include secrets.
- Docs clearly state local evidence is not a compliance system by itself.
