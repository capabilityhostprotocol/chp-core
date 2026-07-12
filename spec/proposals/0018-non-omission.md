# 0018: Non-Omission / Completeness Proofs (`chp-completeness-v1`)

- **Status:** shipped (spec v0.4.3, chp-core 0.26.0, npm alpha.18)
- **Issue:** rad:77ddcc16
- **Affects:** chp-v0.2.md §12 (registers **`chp-completeness-v1`** — a signed bundle
  MAY assert it is the complete correlation, audited against the witnessed store
  head); `evidence-bundle` schema (optional `completeness` block). **Additive** —
  the block is omit-when-absent, so every published vector and signed bundle is
  byte-identical. No store-head or chain-witness change. Spec **v0.4.2 → v0.4.3**.

## Problem

Everything CHP proves today is *"what is in this bundle is real."* It cannot
prove *"nothing was hidden."* A signed bundle's `verify_bundle` already enforces
genesis-contiguity (the first event's `prev_hash` is `null`) and per-event
link-continuity (`prev_hash` is inside each `content_hash`), so **leading,
interior, and suffix drops already fail verification** — a broken link or a
non-genesis first event. But two omissions survive, because both amount to
*"the recorded tail is hidden"*:

1. **Tail-truncation** — export a valid genesis→B prefix and drop C. `[A,B]` is
   internally consistent; `root_hash` is recomputed over `[A,B]`; nothing signed
   says how long the chain *should* be.
2. **Whole-correlation omission** — never export a correlation at all.

Selective disclosure (0011) makes this *easier* — a host can already withhold
payloads; withholding whole tail events is the unaddressed sibling. This is the
most common skeptic question about any evidence system: *"so a host just doesn't
log the bad thing?"* CHP should have a crisp, bounded answer.

## Design

The teeth already exist, uncommitted. The witnessed store head
(`chp-store-head-v1`, §12) commits `leaves = {correlation_id → tail content_hash}`
at a global `sequence`, and a witness stores those `leaves` beside the receipt.
So a correlation's true tail is *already* countersigned by every witness — we
simply never bind a bundle to it or audit against it. This mirrors the
`revocation_head` / revocation-freshness pattern (0010) exactly, but is *smaller*:
the head already commits per-correlation tails, so the commitment binds on the
**bundle** and the audit reuses the head's existing `leaves` — no new head digest.

**The claim.** A signed bundle MAY carry a **`completeness`** block:

```json
"completeness": {
  "scheme": "chp-completeness-v1",
  "correlation_id": "…",
  "as_of_sequence": 42,
  "head_hash": "…"
}
```

`head_hash` is the tail event's `content_hash`; `as_of_sequence` is the host's
assertion *"no events for this correlation exist through global sequence N"*
(N ≥ the tail's sequence). The block is bound into the signed bundle header
(`_HEADER_FIELDS`) **omit-when-absent** — a bundle without it is byte-identical,
and a pre-0018 signature still verifies.

**Self-check** (in `verify_bundle`, when the block is present): `head_hash`
equals the last event's `content_hash`, `correlation_id` matches the events, and
`as_of_sequence` ≥ the tail's `sequence`. With the genesis-contiguity `verify`
already enforces, this proves the bundle is a complete genesis→`head_hash` chain
**as the host claims it**. Self-attestation is necessary but not sufficient — the
host controls both the events and the claim.

**Audit — the teeth** (`audit_completeness(bundle, receipts)`, mirroring
`audit_revocation_freshness`): over witnessed store-head receipts that carry
`leaves`, recompute `store_head` from the snapshot and require it equals the
peer-signed value (tamper check), then for the bundle's `correlation_id` X:

- a witnessed head at `sequence ≥ as_of_sequence` with `leaves[X] == head_hash`
  → **complete** — a witness countersigned this exact tail at/after the claim.
- a witnessed head at `sequence > as_of_sequence` with `leaves[X] != head_hash`
  → **incomplete** — X advanced after the claimed-complete point; because the
  per-correlation chain is append-only, later events were omitted (tail-truncation
  proven).
- X present in a witnessed head's `leaves` but no bundle produced for it →
  **whole-correlation omission**, detectable at the `leaves` level.
- no witnessed head covers X at/after `as_of_sequence` → **unwitnessed**.

**The honest boundary.** An *unwitnessed* correlation's tail-truncation is
uncatchable — no protocol can force a host to record events, or to have had them
witnessed. Completeness catches omission of anything a witness saw; forcing the
recording itself is out of scope, exactly as denial-of-revocation (0010) is
catchable only for witnessed heads. The spec states this plainly rather than
implying a guarantee it cannot make.

## Compatibility

Additive. The `completeness` block is optional and omit-when-absent, so no
canonicalization, hashing, or signing bytes move — every `spec/test-vectors/`
fixture verifies unchanged (the byte gate). The `evidence-bundle` schema gains an
optional `completeness` property; the store head and chain-witness statement are
untouched. No new denial code or evidence type; the `hash_scheme` axis is
orthogonal (completeness commits over `content_hash`es, withheld payloads
included). A **patch** bump (v0.4.3) — a new commitment + a witness-side audit,
no wire surface added, consistent with 0010's v0.2.9.

Deferred by design: **third-party inclusion proofs** over only the signed
`store_head` root (the audit is witness/receipt-side because `/head` does not
serve `leaves`; a Merkle-ized head that lets a party holding only the root verify
inclusion is the separate transparency-log arc); attesting that recording *itself*
happened (the honest boundary — out of scope for any protocol); cross-mesh
completeness for a correlation spanning hosts (task-bundle-level); a per-correlation
running count committed into each event (redundant — the tail `content_hash`
transitively commits the whole chain via `prev_hash`).

## Shipped as

- **Spec v0.4.3** — chp-v0.2.md §12 registers `chp-completeness-v1` (the bundle
  claim + the witness-side audit + the honest boundary); `evidence-bundle` schema
  gains an optional `completeness` block.
- **chp-core 0.26.0** — `build_completeness` + `bundle_header` omit-when-absent
  binding + `build_bundle` param + `verify_bundle` self-check (signing.py);
  `audit_completeness` (witnessing.py, mirroring `audit_revocation_freshness`);
  `/export` emits a completeness claim; `chp completeness verify` runs the audit.
- **npm alpha.18** — chp-sdk `buildCompleteness`/`auditCompleteness` + bundle
  build/verify completeness (byte-parity with Python); chp-host-ts emits it on
  export.
- **Vectors + guards** — `signed-bundle-complete.json` (verified in Python, the
  TS SDK, and the stdlib `verify.mjs`); `spec_defines_completeness` +
  `completeness_vector_verifies` (alignment 82 → 84); wire check
  `check_completeness` PASSES against both reference hosts.

Deferred (unchanged from Design): third-party inclusion proofs over the signed
`store_head` root (a Merkle-ized head — the separate transparency-log arc);
attesting that recording itself happened (the honest boundary); cross-mesh
completeness; a per-correlation committed count (redundant — the tail
`content_hash` transitively commits the chain).
