# 0033: Rekor / Sigstore Transparency-Log Submission

- **Status:** shipped (spec v0.8.3, chp-core 0.41.0)
- **Issue:** rad:a20dab61
- **Affects:** chp-v0.2.md §12 (a new `anchor.type = "rekor"` for the store-head-anchor
  family) + a new `rekor.py`. **Additive** — a host that never submits is unchanged; no
  new reserved code. Spec **v0.8.2 → v0.8.3** (a patch).

## Problem

CHP's evidence is signed and Merkle-anchored, but every anchor so far is **in-mesh** (a
witness quorum, a did:key countersignature). A third party still has to trust *someone
in the mesh* about what the head was at a point in time. A **public transparency log**
(Rekor / Sigstore) removes that: an append-only, publicly-monitored log gives an
inclusion proof that anyone — with no relationship to the host — can check. Proposals
0019/0021/0022/0023 all named Rekor as the eventual external anchor; this delivers it.

## Design

**Reuse the DSSE export — it is already Rekor's native body.** A signed CHP bundle
exports (proposal 0021) as a DSSE-wrapped in-toto attestation whose subject digest *is*
the `root_hash`. That is exactly a Rekor `intoto`/`dsse` entry — no reshaping. `submit`
POSTs it to `…/api/v1/log/entries`.

**Fold the proof into the existing anchor.** Rekor returns an RFC 6962 inclusion proof +
a signed entry timestamp (SET). Both go into a **`store-head-anchor` with `anchor.type =
"rekor"`** — the same statement family that already models "an external checkpoint
attests our root", but with a log-inclusion proof instead of an SSHSIG. The anchor
carries `{log_id, log_index, tree_root, tree_size, inclusion_index, inclusion_hashes[],
set, entry_body, dsse_envelope}`.

**Verify entirely offline against a pinned log key.** `verify_rekor_anchor` (dispatched
from `verify_store_head_anchor` when `anchor.type == "rekor"`) runs four independent
checks: **inclusion** — `SHA256(0x00‖entry_body)` is committed at
`(inclusion_index, tree_size)` under `tree_root`, recomputed via `merkle` (Rekor is RFC
6962, the *same* verifier `chp-store-head-v2` uses); **set** — an ECDSA-P256/SHA256
signature over the canonical `{body, integratedTime, logIndex, logID}` under the log's
pinned public key; **entry_binds_dsse** — the logged entry records this DSSE (its
envelope hash matches); **root** — the DSSE commits `store_head` as its in-toto subject
digest. No network at verify time — the anchor + the pinned key are self-contained.

**Honest boundary.** CHP specifies the *carrier* and the *offline verification* of a
Rekor inclusion proof — **not** the operation of a log. Submission is **opt-in** and
reaches the network (a permanent, immutable, public record); a host that never submits
is fully conformant. The verifier pins the log's public key; trusting a log is a
deployment decision.

## Compatibility

Additive. A new `anchor.type` in the open anchor list (the spec already says "further
anchor types extend the same list" and "unknown anchor types are unverifiable
provenance, never a hard failure"), no wire-object or reserved-code change, no chp-core
dependency added (Rekor I/O uses stdlib urllib; the ECDSA verify uses the already-present
`cryptography`). A **patch** bump (v0.8.3).

## Deferred by design

**Gossip** — a monitor network cross-checking each other's Rekor checkpoints (the
multi-party extension; needs the monitor-fleet infra of 0023/0024); **Rekor v2 /
tiled-log** entry shapes; **checkpoint (signed tree head) verification** beyond the SET
(the SET already binds the entry; a full checkpoint co-signature is additive); binding a
Rekor **inclusion** to a specific *witnessed sequence* (this anchors the root, not the
sequence); the public-good instance's rate/availability as a hard dependency.

## Shipped as

- **Spec v0.8.3** — chp-v0.2.md §12 `rekor` anchor type.
- **chp-core 0.41.0** — `rekor.py` (`submit_bundle`, `rekor_anchor_from_response`,
  `verify_rekor_anchor`, `set_message`); `verify_store_head_anchor` rekor dispatch
  (needs the pinned log key); CLI `chp witness anchor rekor` (submit, network-gated) +
  `chp witness anchor verify --rekor-key`.
- **Tests + guard + vector** — `test_rekor.py` (offline verify + dispatch + tamper breaks
  each check, against a local structurally-real log); `rekor-anchor.json` vector verifies
  in Python + `verify.mjs` (2-impl offline agreement); guards `spec_defines_rekor_anchor`
  + `rekor_anchor_vector_verifies`.
