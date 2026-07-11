# 0010: Revocation Freshness — Witnessed Revocation Heads

- **Status:** shipped (2026-07-11, spec v0.2.9)
- **Issue:** rad:e7f1ed4
- **Affects:** chp-v0.2.md §12 (revocation-freshness paragraph; `chain-witness` header + `/head` gain `revocation_head`), `chain-witness` schema (one optional additive field); canonical bytes: **no changes to existing objects** (`revocation_head` is omit-when-absent — the published `chain-witness.json` vector is byte-identical; no new statement kind, denial code, or evidence type)

## Problem

Revocation is best-effort push (§10, proposal 0007): a host that never
receives a mandate-revocation honors the mandate until expiry. The deeper
gap is that **there is no way to prove what revocation set a host held at a
point in time.** A host can silently drop a revocation it received, or an
operator can suppress one, and it is undetectable — the audit question "did
you know this mandate was revoked?" has no answer the host cannot deny.
Proposals 0005 and 0007 both named the fix as future work: *"using witnessed
heads as a mandate-revocation freshness channel"* (0005) and *"revocation
freshness proofs — a host proving it knew the newest set"* (0007). This
proposal delivers it.

## Design

Witnessing (§12) already has peers countersign a host's evidence store head
on a schedule, with the receipt held by the witness where the operator
cannot delete it. Revocation freshness rides that exact channel: **bind a
digest of the held revocation set into the witnessed head**, so the peer who
signs "at sequence N, host H's store digested to ROOT" also signs "…and its
revocation set digested to REVROOT."

- **`chp-revocation-head-v1`**: a deterministic SHA-256 over the held
  revocation *identifiers* (never the statements — a re-serialized statement
  must not move the head). For each mandate revocation, the line
  `m\x00{mandate_id}\x00{principal.public_key}\n`; for each key revocation,
  `k\x00{revoked_key_id}\n`; sort all lines, SHA-256. The identifier keys are
  the ones §10 already dedupes on, so the digest is stable across
  re-serialization. A host holding no revocations has the well-defined
  empty-set digest — a host must be able to prove it *knew the empty set*.
- **`GET /head`** gains `revocation_head` alongside `store_head`. **The
  `chain-witness` statement's signed header gains `revocation_head`**,
  present only when the head carried one (the §10 omit-when-empty byte rule),
  so a pre-0010 statement — and the published vector — is byte-identical. The
  witness passes through whatever `/head` served; it signs the digest, not
  the set (no revocation id leaks to peers).
- **Recompute-and-match on receipt.** `POST /witness` already recomputes the
  host's own store head before persisting a receipt (never store a receipt
  that does not match). It now *also* recomputes the host's current
  `revocation_head` and refuses (`revocation_head_mismatch`, 409) a statement
  whose value differs — a witness cannot countersign a stale set. On
  acceptance the host snapshots its revocation-identifier set beside the
  receipt (as it snapshots leaves for the store head).
- **The freshness audit.** An auditor recomputes `chp-revocation-head-v1`
  over a receipt's snapshot and checks it equals the peer-signed
  `revocation_head` (tamper-evidence — the snapshot is what was witnessed).
  Then, across snapshots and the current held set, **any identifier present
  in an earlier witnessed snapshot but absent later is a `dropped`
  revocation** — a provable denial of revocation. The held set is
  append-only in practice (nothing deletes from the revocation sidecar), so
  shrinkage is unambiguous. `chp revocation verify` runs it; the reference
  gateway's hourly witness loop now countersigns freshness live.

## Compatibility

Fully additive. `revocation_head` is omit-when-absent in the signed header,
so the published `chain-witness.json` vector and every pre-0010 statement are
byte-identical; a host that does not implement freshness simply omits the
field and its witnessing behavior is unchanged (the export-signing floor). No
new statement kind, denial code, or evidence type. Wire conformance grows
23→24.

Deferred by design: lawful revocation-expiry dispositions (distinguishing a
dropped-because-expired revocation from a suppressed one — the retention
analogue, which would need the mandate to adjudicate; today the set is
append-only so any drop is the alarm), cross-mesh freshness quorum
(requiring k witnesses to agree a host is fresh), and revocation-head
anchoring to an external transparency log.

## Shipped as

- Spec: chp-v0.2.md **§12 "Revocation freshness"** + `chain-witness` header
  and `/head` gain `revocation_head`; CHANGELOG **[0.2.9]**;
  `chain-witness.schema.json` gains one optional additive field
- Bytes: existing `chain-witness.json` byte-identical (`revocation_head`
  omit-when-absent); new `chain-witness-revfresh.json`; no new statement
  kind, denial code, or evidence type
- Guards: `spec_defines_revocation_freshness` + `revocation_head_vector_verifies`
  (alignment 66→68); wire suite **23→24** (`check_revocation_freshness`:
  `/head` returns revocation_head, correct one accepted, wrong one refused
  409; both reference hosts 24/24)
- Implementations: Python `compute_revocation_head` / `revocation_ids` /
  `revocation_head()` / `audit_revocation_freshness` + `chain_witness_header`
  conditional + `build_chain_witness` kwarg + `/head` field +
  `_receive_witness` recompute-match + receipt snapshot + witness-loop
  passthrough + `chp revocation verify`; TS `computeRevocationHead` +
  `chainWitnessHeader` conditional + `buildChainWitness` opt +
  `verifyChainWitness` (cross-verified against the Python-signed vector) +
  server `/head`/`/witness`
- Refinement vs proposal: none — landed as designed; deferrals stayed named
  (lawful revocation-expiry dispositions, cross-mesh freshness quorum,
  transparency-log anchoring)
