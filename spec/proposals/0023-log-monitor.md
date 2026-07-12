# 0023: Log Monitor — Fork/Rewrite Detection over Anchored Store-Head History

- **Status:** shipped (spec v0.6.2, chp-core 0.31.0, npm alpha.22)
- **Issue:** rad:915fb880
- **Affects:** chp-v0.2.md §12 (adds a **log monitor**: a party walks a host's
  external store-head-anchor history and, for each anchor `(seq N, root R)`,
  reconstructs the head as-of N from the live store and checks it still equals R —
  a mismatch is a provable **rewrite**; the monitor emits a signed
  `store-head-monitor-report`); a new `store-head-monitor-report` object. **No new
  denial code** (a monitor finding is a report, not a request denial). Composes
  0019's `get_store_head(fresh)` reconstruction with 0013's immutable external
  anchors — no new tree math. Spec **v0.6.1 → v0.6.2**.

## Problem

0019 (inclusion) and 0022 (consistency) gave the transparency log its *math* — a
third party can prove a leaf is committed and that one head extends another. But
nothing yet *operationalizes* it: no party continuously checks that a host's log
stays faithful over time. The store head is append-only **by construction**, yet a
malicious operator with write access to their own SQLite store could edit or drop
an old event — which silently changes that correlation's head_hash and therefore
the store head as-of every sequence ≥ the edit. Inclusion and consistency proofs
are computed *from the store*, so a rewritten store produces internally-consistent
(but false) proofs. What catches the rewrite is an **external, immutable
reference**: the store-head-anchors (§12, 0013) — SSHSIG countersignatures over
`(host_id, sequence, root)` that live outside the mesh and cannot be edited by the
operator. The missing piece is the party that *checks the live store against
them*.

## Design

A **log monitor** holds (a) the host's anchor history and (b) read access to the
host's store (a witness, an auditor, or the host attesting to itself). For each
anchor `(N, R, scheme)` it recomputes the head **as-of N** from the live events —
`get_store_head(at_sequence=N, fresh=True, scheme=scheme)`, which reconstructs the
leaves `{correlation_id: head_hash}` among events with `sequence ≤ N` and folds
them under the anchored scheme (the `fresh` audit path never trusts the cached
`correlation_heads`, since a store editor could edit the cache too). If the
reconstructed root **≠** the anchored `R`, the store no longer reproduces a root it
once externally committed: a **rewrite**, provably, at sequence N. Anchors are
walked in `sequence` order; a monitor over a faithful log confirms every anchored
root still reconstructs and reports **consistent through** the highest sequence.

**The signed report** (`store-head-monitor-report`) — the same signed-statement
family as chain-witness/anchor (a `signature` over a canonical header, a `monitor`
identity block):

```json
{
  "kind": "store-head-monitor-report",
  "host_id": "<monitored host>",
  "verified_through_sequence": 128,
  "anchor_count": 4,
  "verdict": "consistent",
  "monitored_at": "<ISO-8601>",
  "canonicalization": "chp-stable-v1",
  "monitor": { "host_id": "...", "public_key": "...", "host_identity": { … } },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "…" }
}
```

A **forked** verdict carries a `divergence` block (omit-when-consistent, the §10
byte rule) — `{sequence, anchored_root, reconstructed_root}` — naming exactly where
the live store stopped reproducing the anchored root. The report is offline-
verifiable: recompute the header, check the monitor's ed25519 signature; the
verdict + divergence are then a signed, portable accusation an operator cannot
retract. Its value, like a witness statement, is that it lives with the
**monitor**, not the monitored host.

**Reference feature, opt-in.** Like the prober and the witnessing loop, a host
carries an optional self-monitor; any party with the anchors + a store copy runs
`chp head monitor`. A host that neither anchors nor is monitored stays conformant.

## Compatibility

Additive and non-destabilizing. No wire object, bundle byte, leaf, tree, head
signing, witness header, or anchor message changes — the monitor *reads* existing
anchors and *reconstructs* existing heads; the only new artifact is the monitor's
own signed report. No new denial code (no `RESERVED_CODES` change — the report is
a signed statement, not a gate outcome). A **patch** bump (v0.6.2): it operates the
existing transparency log rather than extending its format.

## Deferred by design

A **remote monitor** that holds only anchors + host-served consistency proofs (no
store copy) — the endpoint that serves `store_head_consistency_proof` between two
sequences (0022's math, reconstruct-at-sequence on the serving side); **gossip**
between monitors (cross-checking each other's reports); continuous monitor
scheduling/alerting (operational, not protocol); real Rekor/Sigstore submission
(unchanged from 0019/0022).

## Shipped as

- **Spec v0.6.2** — chp-v0.2.md §12 (the log monitor: reconstruct-vs-anchor,
  the signed report); new `store-head-monitor-report` schema.
- **chp-core 0.31.0** — `signing.py`: `build_store_head_monitor_report` /
  `verify_store_head_monitor_report` / `store_head_monitor_report_header`;
  `witnessing.py`: `monitor_anchor_history` (walk anchors, reconstruct each head
  via `get_store_head(fresh, scheme)`, forked at the first divergence); CLI
  `chp head monitor`.
- **npm alpha.22** — chp-sdk `verifyStoreHeadMonitorReport` (byte-parity).
- **Vectors + guards** — `store-head-monitor-report.json` (a signed consistent +
  a forked report, verified in Python, the TS SDK, and stdlib `verify.mjs`);
  `spec_defines_log_monitor` + `monitor_report_vector_verifies` (alignment
  94 → 96).

Deferred (unchanged): a remote monitor (anchors + host-served consistency proofs,
no store copy); gossip between monitors; continuous scheduling/alerting; real
Rekor/Sigstore submission.
