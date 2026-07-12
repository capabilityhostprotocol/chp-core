# 0024: Remote Log Monitor — Fork Detection with No Store Copy

- **Status:** shipped (spec v0.6.3, chp-core 0.32.0, npm alpha.23)
- **Issue:** rad:e40472a7
- **Affects:** chp-v0.2.md §12 (a **remote monitor**: holds only a host's immutable
  anchor history and asks the host to *serve* a consistency proof between each
  anchored pair, verifying it against the anchored roots — no store copy). A new
  reference endpoint `GET /head/consistency?first=<seq>&second=<seq>`. **Reuses**
  the `store-head-consistency` (0022) and `store-head-monitor-report` (0023)
  objects — no new schema. Spec **v0.6.2 → v0.6.3**.

## Problem

0023's monitor catches a rewrite by reconstructing the head from the store and
comparing to the immutable anchor — but it must **hold the store** (a witness, an
auditor with a full copy, or the host itself). That does not scale to independent
oversight: a regulator or customer auditing many hosts cannot replicate every
operator's multi-gigabyte evidence store. The immutable external anchors are
already compact (a few hundred bytes each) and can be collected off-mesh. What is
missing is a way to check *append-only over time* holding **only** the anchors.

## Design

A **remote monitor** holds a host's anchor history `[(s₁, R₁), (s₂, R₂), …]` (the
SSHSIG-countersigned roots, immutable) and, for each consecutive pair, asks the
host to **serve a consistency proof** between the two sequences. It then runs
`verify_store_head_consistency(Rᵢ, Rᵢ₊₁, proof)` — the 0022 check — against the
**anchored** roots, never its own reconstruction.

The catch that makes this sound: the proof's `first_root`/`second_root` must equal
the immutable `Rᵢ`/`Rᵢ₊₁`. A host that rewrote history reconstructs a **different**
head at sequence sᵢ, so any consistency proof it computes carries `first_root ≠
Rᵢ` — `verify_store_head_consistency` rejects it (carried-root mismatch). The
operator cannot forge a proof whose roots match the anchors it no longer
reproduces. So a rewrite is detected **with no store copy** — the host either
serves a proof that fails against the anchors, or cannot serve one at all. Either
way the monitor emits the 0023 `store-head-monitor-report` (`forked`, the
`divergence` naming the pair); a full faithful chain yields `consistent`.

**The serving endpoint** (reference feature, opt-in, like `/head/inclusion/`):

```
GET /head/consistency?first=<seq>&second=<seq>   (authed)
→ 200 { the store-head-consistency object between the two reconstructed heads }
```

The host reconstructs the head at both sequences — `get_store_head(at_sequence=s,
fresh=True, scheme=chp-store-head-v2)` — and returns
`store_head_consistency_proof(head@first.leaves, head@second.leaves)`. Leaves stay
local (the proof carries only subtree hashes); the sequence discloses activity
volume, so the endpoint is authed (the mesh-count privacy rule, as for `/head`).

**Requires `chp-store-head-v2` anchors.** Consistency proofs are a v2 (Merkle)
feature (0022) — a v1 flat-fold anchor has none. The remote monitor therefore
**refuses** a history with any non-v2 anchor rather than emit a false `forked`
against a host it simply cannot check this way; a host that wants remote
monitoring anchors under v2.

## Compatibility

Additive. No wire object, bundle byte, or signature changes; the endpoint serves a
proof over roots that already exist, and the monitor reuses existing verify code.
No new denial code, no new schema (the served object is `store-head-consistency`;
the finding is a `store-head-monitor-report`). A **patch** bump (v0.6.3): it adds a
reference endpoint + a monitoring mode, not a format.

## Deferred by design

**Gossip** between remote monitors (cross-checking each other's reports); monitor
scheduling/alerting (operational); a host that *pushes* proactive proofs (this is
pull-only); real Rekor/Sigstore submission (unchanged). A remote monitor also
cannot force an offline host to answer — an unreachable host is `host_unreachable`
(§11), not `forked`; the report distinguishes *proven-forked* from *unprovable*.

## Shipped as

- **Spec v0.6.3** — chp-v0.2.md §12 (the remote monitor + `/head/consistency`);
  reuses the `store-head-consistency` (0022) + `store-head-monitor-report` (0023)
  objects (no new schema).
- **chp-core 0.32.0** — `http.py` `GET /head/consistency?first=&second=` (authed,
  reconstruct both heads + `store_head_consistency_proof`); `witnessing.py`
  `monitor_anchor_history_remote(anchors, fetch_proof)` (verify served proofs vs
  the immutable anchors; requires v2 anchors — refuse v1 rather than falsely
  accuse); conformance `check_remote_monitor` (wire).
- **npm alpha.23** — chp-host-ts serves `/head/consistency`; chp-sdk
  `fetchConsistencyProof` + `monitorAnchorHistoryRemote` (byte-parity).
- **Guard** — `spec_defines_remote_monitor` (alignment 96 → 97).

Deferred (unchanged): gossip between monitors; monitor scheduling/alerting; a
host that pushes proactive proofs (pull-only); real Rekor/Sigstore submission.
