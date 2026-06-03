# CHP Evidence Roadmap

This document captures the intended evolution of CHP's evidence model beyond v0.1. None of
these are v0.1 requirements — they are forward signals so early adopters can design with
the direction in mind.

## v0.1 (current)

Evidence is local-first and append-only:

- Every invocation emits structured `ExecutionEvidence` to a local SQLite store
- Events are ordered by sequence number within a correlation ID
- Payloads are redacted by default for common sensitive keys
- Replay returns the ordered event stream for any correlation ID
- Evidence integrity: **local append-only** — the store is not tamper-evident

This is sufficient for local observability, debugging, and development governance.
It is not a compliance record and should not be treated as one.

## v0.2 targets: tamper-evidence

The v0.2 evidence model introduces integrity guarantees:

**Hash chaining** — each event carries the hash of the previous event in the
same correlation stream, forming a verifiable chain. Any insertion, deletion, or
modification breaks the chain and is detectable.

**Host identity** — the `LocalCapabilityHost` will carry an identity key pair.
Evidence events will be signed by the host at emission time. The signature covers
the event payload, timestamp, sequence number, and previous hash.

**Verification CLI** — `chp verify-evidence <correlation-id>` will walk the
chain, verify each signature, and report the first broken link. A clean result
means the evidence is intact since the host emitted it.

**Signed export** — `chp export-evidence <correlation-id>` will produce a
portable bundle (JSON or CBOR) with the full chain and host public key, suitable
for sharing with an auditor or attaching to a compliance record.

These changes are backward-compatible with v0.1 replay. Unsigned v0.1 events
will be treated as legacy and will pass a lenient verification mode.

## v0.3+ targets: distributed evidence

Longer-term evidence goals once multi-host replay exists:

- **Cross-host trace stitching** — correlate evidence across hosts by
  `trace_id` in `CorrelationContext`
- **Evidence delegation** — a host can attest that a downstream host executed
  a sub-capability, anchoring the downstream evidence into the parent trace
- **Policy-gated evidence export** — evidence bundles require explicit approval
  before leaving the local host boundary
- **Retention tiers** — configurable evidence lifetime with archive export
  before deletion

## What this means for v0.1 adopters

If you are building on `chp-core` today:

- Your `ExecutionEvidence` events and `SQLiteEvidenceStore` will remain valid
  in v0.2 — no migration required for existing stores
- The `event_id`, `correlation_id`, `sequence`, and `timestamp` fields will be
  the inputs to the hash chain — use them as stable identifiers
- Do not rely on the absence of an `integrity` field as a permanent condition;
  v0.2 will add it

The protocol specification (`spec/chp-v0.1.md`) will be versioned independently.
A v0.2 draft will be published before any breaking changes ship.
