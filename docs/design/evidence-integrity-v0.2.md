# Evidence Integrity v0.2 Proposal

> **SUPERSEDED** by [`spec/chp-v0.2.md`](../../spec/chp-v0.2.md) (shipped). This
> proposal's field names differ from what shipped (`event_hash` →
> `content_hash`, `previous_event_hash` → `prev_hash`, `json-canonicalization-
> scheme` → `chp-stable-v1`) — do NOT implement from this document. Kept for
> history per [`spec/proposals/README.md`](../../spec/proposals/README.md).

Status: superseded (was: proposal).

CHP v0.1 evidence is local append-only evidence. It is useful for visibility and
replay, but it is not tamper-proof and should not be described as
compliance-grade assurance.

v0.2 should define an optional tamper-evident evidence model without changing
the v0.1 local-first developer experience.

## Goals

- Detect local evidence modification, deletion, and reordering.
- Bind evidence to host identity.
- Allow offline verification of an exported trace.
- Preserve simple local append-only storage.
- Keep cryptographic integrity optional for hosts that only need v0.1 visibility.

## Non-Goals

- Distributed consensus.
- Hosted notarization as a protocol requirement.
- Enterprise compliance exports.
- Full key management or RBAC.
- Mandatory signing for all v0.2 hosts.

## Hash Chain

Each evidence event can include an integrity envelope:

```json
{
  "hash_algorithm": "sha256",
  "event_hash": "hex...",
  "previous_event_hash": "hex...",
  "canonicalization": "json-canonicalization-scheme",
  "sequence": 42
}
```

The `event_hash` should be computed over canonicalized evidence fields,
excluding the integrity envelope itself. The `previous_event_hash` links to the
prior event in the same local store or exported bundle.

This detects mutation and reordering within a sequence.

## Signed Evidence Bundles

A host can export a bundle:

```json
{
  "host_id": "local-host",
  "protocol_version": "0.2",
  "created_at": "2026-05-16T00:00:00Z",
  "events": [],
  "root_hash": "hex...",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "host-key-id",
    "signature": "base64..."
  }
}
```

Signing the bundle root hash avoids signing every event individually while still
allowing event-level hash-chain verification.

## Host Identity

v0.2 should define minimal host identity metadata:

- stable `host_id`
- public verification key or key reference
- key creation timestamp
- optional key rotation metadata

The protocol should not require a specific identity provider. Hosted products
can add managed identity, RBAC, and retention later.

## Verification CLI

A v0.2 verification CLI should support:

```bash
chp verify evidence-bundle.json
```

Checks:

- event schema validity
- sequence continuity
- event hash validity
- hash-chain continuity
- bundle root hash
- signature validity when a public key is available

## Open Questions — Resolved

**Which JSON canonicalization scheme?**
Use JCS (JSON Canonicalization Scheme, RFC 8785). It is deterministic, widely
implemented, and produces stable byte sequences across platforms.

**Hash chains: per correlation ID, per host store, or both?**
Per host store for v0.2. Correlation ID grouping is a query concern, not a
storage structure. Per-store chains are simpler to verify and easier to export
as a single bundle.

**Key rotation without hosted identity?**
A `valid_until` timestamp in host identity metadata is sufficient for v0.2.
A rotated key creates a new identity record; the old one becomes inactive.
No revocation infrastructure required until a commercial layer is added.

**Should unsigned bundles be valid but lower assurance?**
Yes. Three graduated assurance levels:
- `none` — local append-only evidence (v0.1 baseline, always valid)
- `hash-chain` — sequence integrity without signing (detects mutation)
- `signed` — full tamper-evident bundle with ed25519 signature

A v0.2 host declares its assurance level in the `/host` response. Verifiers
reject lower-than-expected assurance levels rather than silently degrading.

## Recommendation

Keep v0.1 unchanged. Add integrity as an optional v0.2 layer:

- v0.1: local append-only evidence
- v0.2: tamper-evident local evidence bundles
- commercial layer: hosted retention, managed identity, compliance exports, and
  multi-host graph integrity
