# 0019: Transparency-Log Store Head (`chp-store-head-v2`, RFC 6962 Merkle) + Inclusion Proofs

- **Status:** shipped (spec v0.5.0, chp-core 0.27.0, npm alpha.19)
- **Issue:** rad:d58655cd
- **Affects:** chp-v0.2.md §12 (registers **`chp-store-head-v2`** — a Merkle store
  head + inclusion proofs so a party holding only the signed root can verify one
  correlation's leaf is committed, with no leaves snapshot and no witness);
  `store-head-anchor` schema (self-describing `store_head_scheme`) + a new
  `store-head-inclusion` object. **Additive** — `chp-store-head-v1` stays the
  default and byte-identical; the witness/anchor signing machinery is unchanged
  (it already treats the root opaquely). Closes 0018's third-party-verification
  deferral and 0013's "real Merkle-inclusion proofs" deferral. Spec **v0.4.3 →
  v0.5.0**.

## Problem

CHP tamper-evidence today rests on *"trust our witness set."* The store head
(`chp-store-head-v1`, §12) is a **flat SHA-256 fold** over every per-correlation
leaf (`SHA256(sorted correlation_id\x00head_hash\n …)`). To verify that ONE
correlation's tail is committed under a head, a verifier must obtain the **entire
leaves snapshot** and re-fold all of it — which only a witness who received the
head holds (the completeness audit in 0018 is witness-side for exactly this
reason, its explicit deferral; 0013 named "real Rekor/Sigstore Merkle-inclusion
proofs" out of scope). A relying party outside the mesh cannot ask *"is this one
correlation in the head?"* without trusting a witness to hand over everything.

## Design

**`chp-store-head-v2`** replaces the flat fold with an
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2) (Certificate
Transparency) **Merkle tree** over the SAME per-correlation leaves, in the SAME
sorted order — so the head is a tree root instead of a running hash:

- Leaf bytes are unchanged: `d(i) = f"{correlation_id}\x00{head_hash or ''}\n"`,
  over `sorted(leaves)`.
- **Domain-separated** hashing (RFC 6962 §2.1, second-preimage-safe): leaf hash
  `SHA256(0x00 ‖ d)`, interior node `SHA256(0x01 ‖ left ‖ right)`; for `n > 1`
  split at `k` = the largest power of two `< n`; the empty tree is `SHA256("")`.
  This is the audited standard (the RFC-8785/JCS move applied to trees), so a
  Python, TS, and stdlib implementation compute the identical root.
- The **root** is the `store_head` value when the head declares
  `scheme: "chp-store-head-v2"`.

**Nothing that signs the head changes.** The chain-witness header, the
store-head-anchor message, the quorum comparison, and `/head` all treat
`store_head` as an **opaque string** — so a v2 root is witnessed and anchored
byte-for-byte as a v1 one; only the root's *value* differs. A single
`store_head_root(scheme, leaves)` dispatcher (mirroring `_canon_for`, §2) folds
v1 or builds the v2 root and raises on an unknown scheme; the four
recompute-from-leaves sites dispatch on it. `get_store_head` defaults to
`chp-store-head-v1` (every existing head, receipt, and vector byte-identical); a
host opts into v2 by config. The signed root **self-validates the scheme** — a
recompute under the wrong scheme cannot equal the signed value — so no scheme
field is added to the signed witness header (v1 stays byte-identical).

**Inclusion proofs — the point.** `store_head_inclusion_proof(leaves,
correlation_id)` returns `{leaf_index, tree_size, audit_path:[hex…]}` (RFC 6962
§2.1.1); `verify_store_head_inclusion(root, correlation_id, head_hash, proof)`
recomputes the root from the leaf `SHA256(0x00 ‖ correlation_id\x00head_hash\n)`
up the audit path and checks equality — **with no leaves snapshot**. The proof
binds the leaf bytes, so it proves BOTH *which correlation* and *which tail*; a
forged `head_hash` or wrong `correlation_id` fails.

**Third-party, witness-free verification.** The **store-head-anchor** (§12, 0013)
is the carrier: it already signs the opaque root with an external `did:key`, so
`{anchored v2 head, a correlation's (id, head_hash), an inclusion proof}` lets a
party who is not a witness and holds no leaves verify — offline — that the
correlation's tail is committed under an externally-anchored root. The anchor
gains an omit-when-absent `store_head_scheme` so a stranger knows how to
recompute. The completeness audit (0018) gains a non-witness path: given an
anchor + an inclusion proof, `audit_completeness` returns `complete` /
`incomplete` without a witness receipt — closing 0018's honest-boundary deferral
for anchored correlations.

## Compatibility

Additive. `chp-store-head-v1` is the default and byte-identical: every existing
head, chain-witness, anchor, receipt, and test vector is unchanged, and the byte
gate holds. The signing/witnessing/anchoring machinery is untouched (opaque
root). New optional schema: `store_head_scheme` on `store-head-anchor` (omit-when-
absent) + a `store-head-inclusion` object. A **minor** bump (v0.5.0) — a second
store-head scheme plus third-party inclusion verification is a headline
capability (as `chp-event-hash-v2` was v0.3.0 and `chp-jcs-v1` v0.4.0), though no
existing bytes move.

Deferred by design: Merkle **consistency proofs** (append-only between two roots
— the full CT log property; this ships the verifiable tree + offline inclusion,
not the log-append proof); real Rekor/Sigstore **submission + gossip** (the
anchor is the signed-checkpoint carrier, not a hosted transparency log); log
monitors / witnesses-of-the-log; Merkle-izing the per-event bundle `root_hash`
(orthogonal — this is the store head, the cross-correlation commitment).

## Shipped as

- **Spec v0.5.0** — chp-v0.2.md §12 registers `chp-store-head-v2` (RFC 6962
  Merkle) + inclusion proofs + the anchor carrier; new `store-head-inclusion`
  schema + `store_head_scheme` on `store-head-anchor`.
- **chp-core 0.27.0** — `merkle.py` (RFC 6962 root/proof/verify, domain-separated,
  self-check); `store_head_root(scheme)` dispatcher; `get_store_head(scheme=)`
  (v1 default); `store_head_inclusion_proof` + `verify_store_head_inclusion`
  (third-party, no leaves); `store_head_scheme_matching` (self-validating); the
  witness audits match the signed root against known schemes; the anchor gains
  `store_head_scheme`; `audit_completeness_via_anchor` (non-witness); `/head?scheme=`
  + `/head/inclusion/{corr}`; `chp head inclusion`.
- **npm alpha.19** — chp-sdk `merkle.ts` (byte-parity) + `computeStoreHead`
  dispatch + `verifyStoreHeadInclusion` + `auditCompletenessViaAnchor`;
  chp-host-ts serves the v2 head + inclusion routes.
- **Vectors + guards** — `store-head-v2.json` + `store-head-inclusion.json`
  (verified in Python, the TS SDK, and stdlib `verify.mjs`, RFC 6962 pinned);
  `spec_defines_store_head_v2` + `store_head_v2_root_recomputes` +
  `inclusion_vector_verifies` (alignment 84 → 87); wire check
  `check_store_head_inclusion` PASSES both reference hosts.

Deferred (unchanged from Design): Merkle consistency proofs (append-only between
two roots); real Rekor/Sigstore submission + gossip; log monitors; Merkle-izing
the per-event bundle `root_hash`.
