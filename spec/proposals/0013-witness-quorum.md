# 0013: Witness Quorum + External Anchoring

- **Status:** shipped (2026-07-11, spec v0.3.2)
- **Issue:** rad:3fc2fad
- **Affects:** chp-v0.2.md §12 (a **`chp-witness-quorum-v1`** audit + a **`chp-store-head-anchor-v1`** statement) + a new `store-head-anchor` schema; CHANGELOG **[0.3.2]**. Canonical bytes: **additive** — quorum aggregates the `chain-witness` statements that already exist (no new object; existing vectors byte-identical); the store-head anchor is a new *optional standalone* statement. No new denial code, no store-head change. Spec **v0.3.1 → v0.3.2**.

## Problem

§12 witnessing (proposal 0005) has peers countersign a host's store head, with
the receipt held by the witness where the operator cannot delete it. But **one
witness is a single point of collusion**, and every witness is a peer *we
control*:

1. **No quorum.** `received.json` (the witnessed host's collection of every
   `chain-witness` statement countersigning it) is a flat append list — no
   distinct-witness accounting, no threshold. A head is "witnessed" if a
   *single* receipt survives recompute-match. An auditor cannot say "≥k
   independent parties vouched for this head."
2. **No external anchor.** Tamper-proofness depends entirely on our peer set —
   if every witness colludes (or is coerced), there is no independent record
   that a head existed at time T.

§12 named both as out of scope ("quorum policies, and external transparency-log
anchoring are deliberately out of scope"). This proposal delivers them.

## Design

Both features build on the existing §12 machinery — quorum aggregates statements
that already exist; anchoring reuses the identity-anchor SSHSIG shape.

### A. Witness quorum (`chp-witness-quorum-v1`) — audit-side

The `chain-witness` statements already exist and already verify individually
(`verify_chain_witness`: signature + witness identity). Quorum is **pure
aggregation over a collected set** — no new wire object:

- **`evaluate_witness_quorum(statements, host_id, sequence, store_head, k, witness_set=None)`**:
  verify each statement, keep only those covering the EXACT
  `(host_id, sequence, store_head)`, **dedupe by the witness's `key_id`**
  (a witness re-submitting counts once — quorum measures distinct identities,
  not statement volume), optionally restrict to an allowed `witness_set` (the
  "n"), and count. Verdict **`quorum_met`** (distinct ≥ k) or **`quorum_short`**
  (< k), with the witness key-id list — the anti-collusion proof: *"≥k
  independent parties countersigned this exact head."*
- **Policy** on the gateway config: `witness_quorum_k` (default 0 = off) + an
  optional trusted `witness_set`. The witness *loop* is unchanged (it still
  countersigns every remote); quorum is an audit property, not a production
  change. `quorum_short` is a verdict, never a gate denial.
- Served over `GET /witnesses` (already returns the statements) + `chp witness
  quorum`. Federated cross-witness collection (defeating a host that hides its
  own receipts — the witnesses' `issued/` records are the cross-check) is a
  named deferral; this ships the aggregation primitive.

### B. External store-head anchoring (`chp-store-head-anchor-v1`)

An external party OUTSIDE the mesh signs the store head, so even if *all*
witnesses collude, an independent record of the head at time T survives. Reuses
the identity-anchor pattern (`verify_did_anchor` → SSHSIG over canonical bytes):

- **`store-head-anchor` statement**: `{kind:"store-head-anchor", host_id,
  sequence, store_head, anchored_at, anchor:{type:"did", did, countersignature}}`.
  The external `did:key`'s ed25519 key **SSHSIG-countersigns**
  `canon({kind, host_id, sequence, store_head, anchored_at})` (the
  `did_anchor_message` shape, SSHSIG namespace `chp-store-head-anchor`), verified
  fully offline by `verify_store_head_anchor`. The anchor key is a designated
  notary or a transparency-log checkpoint key.
- Served beside witnesses (`GET /anchors`). No new denial code — an anchored
  head simply carries independent, out-of-mesh attestation.
- **Real Rekor/Sigstore Merkle-inclusion proofs + gossip are a named deferral**
  — this ships the signed-checkpoint form (an external key vouches for the head),
  the verifiable primitive; full transparency-log inclusion comes later.

## Compatibility

Additive. Quorum introduces no canonical object — it counts existing
`chain-witness` statements, so `chain-witness.json` / `chain-witness-revfresh.json`
and every other vector are byte-identical. The `store-head-anchor` statement is a
new optional standalone object (a host that never anchors is unaffected; a
verifier that never sees one is unchanged). No new denial code, no new evidence
type, no store-head change. Wire conformance grows by one check.

Deferred by design: real Rekor/Sigstore transparency-log Merkle-inclusion proofs
+ gossip; federated cross-witness collection to defeat receipt-hiding;
quorum-gated serving (refusing to serve below quorum); weighted / stake-based
quorum; anchor key rotation/revocation.

## Shipped as

- Spec: chp-v0.2.md **§12 "Witness quorum"** + **"External anchoring"**; status
  line **v0.3.2**; CHANGELOG **[0.3.2]**; new `store-head-anchor.schema.json`;
  chain-witness schema unchanged
- Bytes: existing vectors byte-identical (quorum aggregates existing statements);
  new `witness-quorum.json` + `store-head-anchor.json`; no new denial code, no new
  evidence type, no store-head change, no store schema change (anchors are sidecar)
- Guards: `spec_defines_witness_quorum` + `witness_quorum_vector_verifies` +
  `store_head_anchor_vector_verifies` (alignment 72→75); wire suite **26→27**
  (`check_witness_quorum`: 3 distinct witnesses → `quorum_met`, k-1 → `quorum_short`;
  an external anchor verifies offline + round-trips `/anchors`; both reference hosts)
- Implementations: Python `evaluate_witness_quorum` (witnessing.py) + quorum policy
  on `GatewayConfig` + `store_head_anchor_message`/`build_store_head_anchor`/
  `verify_store_head_anchor` (signing.py, reusing the §3.1 SSHSIG path) +
  `record_anchor`/`load_anchors` + `GET`/`POST /anchors` + `chp witness quorum` /
  `chp witness anchor verify`; TS `evaluateWitnessQuorum` + `verifyStoreHeadAnchor` +
  `storeHeadAnchorMessage` + chp-host-ts `/anchors`; reference `verify.mjs`
  witness-quorum branch (the anchor SSHSIG cross-verifies via the TS SDK)
- Refinement vs proposal: none — landed as designed; deferrals stayed named (real
  Rekor/Sigstore inclusion proofs + gossip, federated cross-witness collection,
  quorum-gated serving, weighted/stake quorum, anchor rotation/revocation)
