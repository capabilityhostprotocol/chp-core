# 0022: Merkle Consistency Proofs — Append-Only Transparency Log

- **Status:** shipped (spec v0.6.1, chp-core 0.30.0, npm alpha.21)
- **Issue:** rad:e864dfd5
- **Affects:** chp-v0.2.md §12 (adds **consistency proofs** to `chp-store-head-v2`:
  given two signed/anchored Merkle roots, prove the log only **appended** between
  them — no old correlation dropped, altered, or reordered); a new
  `store-head-consistency` object. **Additive** — no existing wire object,
  bundle byte, leaf, or signature changes; `chp-store-head-v1` stays the default.
  Completes the transparency log from 0019 (inclusion proved a leaf is *in* the
  tree; consistency proves the tree is *append-only*). Spec **v0.6.0 → v0.6.1**.

## Problem

0019 shipped **inclusion** proofs: a party holding only a signed Merkle root can
verify one correlation's leaf is committed, with no leaves snapshot and no
witness. But inclusion says nothing across *time*. A malicious operator can serve
two perfectly-valid signed heads at different sequences where the later head has
silently **rewritten history** — dropped an old correlation, altered a
committed `head_hash`, or reordered leaves — and each head, checked alone, still
verifies. Inclusion catches *"is this leaf here?"*; it cannot catch *"did you
quietly remove a leaf that used to be here?"*. That is the **append-only**
property, and it is the half of a transparency log 0019 explicitly deferred
(*"Merkle consistency proofs … out of scope, named in proposal 0019"*).

## Design

**[RFC 6962 §2.1.2](https://www.rfc-editor.org/rfc/rfc6962#section-2.1.2)
consistency proofs** over the SAME `chp-store-head-v2` tree. A consistency proof
between an earlier tree of size `m` and a later tree of size `n` (`m ≤ n`) is a
minimal set of subtree hashes from which a verifier recomputes **both** the old
root (size `m`) and the new root (size `n`). If the recomputed old root equals
the earlier signed root **and** the recomputed new root equals the later signed
root, the later tree provably *contains the earlier tree as a prefix* — every
old leaf is still present, unchanged, in the same position. Any drop, edit, or
reorder of an old leaf makes the recomputed old root diverge from the signed one,
and verification fails.

**The proof object** (`store-head-consistency`):

```json
{
  "scheme": "chp-store-head-v2",
  "first_size": 3,
  "second_size": 7,
  "first_root": "<hex>",
  "second_root": "<hex>",
  "proof": ["<hex>", "..."]
}
```

`first_root`/`second_root` are carried so a stranger has the exact roots the proof
reconstructs to (they must equal the two anchored heads). `proof` is the RFC 6962
subtree-hash path (empty when `first_size == second_size` and the roots match).

**Verification** mirrors the module's inclusion discipline — replay the SAME
recursive split the prover used (`SUBPROOF(m, D[0:n], b)`), not the error-prone
`fn/sn` bit walk — returning the reconstructed `(old_root, new_root)` pair and
checking both against the signed roots. `verify_store_head_consistency(old_root,
new_root, proof)` is the third-party entry point: witness-free, offline, over two
anchored roots alone.

**The carrier.** The **store-head-anchor** (§12, 0013) already signs the opaque
root and — since 0019 — self-describes its `store_head_scheme`. So
`{two anchored heads at sequences s₁ < s₂, a consistency proof}` gives a third
party offline, witness-free proof that between the two externally-anchored heads
the operator's log **only grew** — the strongest anti-tamper property short of a
hosted transparency log with gossip. No new signed field: the proof is computed
from the two roots the anchors already commit.

## Compatibility

Additive and non-destabilizing. No leaf bytes, tree construction, head signing,
witness header, or anchor message changes — this is a new *proof* computed over
roots that already exist. `chp-store-head-v1` (the flat fold) has no consistency
proof and stays the default; consistency is a `chp-store-head-v2` capability. The
byte gate shows only the new vector. A **patch** bump (v0.6.1) — it completes an
existing scheme rather than adding a new signed-artifact family (unlike 0019's
minor).

## Deferred by design (unchanged from 0019)

Real Rekor/Sigstore **submission** + a hosted transparency log; **gossip** /
witness-of-the-log protocols (multiple monitors cross-checking a log's heads);
log **monitors** that continuously fetch and consistency-check every new head.
This ships the verifiable append-only *proof* over anchored heads, not the hosted
log infrastructure that would automate fetching and gossiping them.

## Shipped as

- **Spec v0.6.1** — chp-v0.2.md §12 (consistency proofs: append-only across two
  anchored heads); new `store-head-consistency` schema.
- **chp-core 0.30.0** — `merkle.py`: `consistency_proof` (RFC 6962 §2.1.2
  `SUBPROOF`), `verify_consistency` (recursive split replay — both roots
  recompute), `store_head_consistency_proof` / `verify_store_head_consistency`
  (third-party, witness-free); CLI `chp head consistency`.
- **npm alpha.21** — chp-sdk `merkle.ts` (`consistencyProof`, `verifyConsistency`,
  the store-head layer) — byte-parity with Python.
- **Vectors + guards** — `store-head-consistency.json` (two anchored heads 5→7,
  verified in Python, the TS SDK, and stdlib `verify.mjs`); the selfcheck +
  `test_merkle` prove every `m ≤ n` recomputes both roots and a dropped/altered/
  reordered old leaf fails; `spec_defines_consistency_proof` +
  `consistency_vector_verifies` (alignment 92 → 94).

Deferred (unchanged): real Rekor/Sigstore submission + a hosted log; gossip /
witness-of-the-log; continuous log monitors.
