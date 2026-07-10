# 0005: Mesh Witnessing — Tamper-Proof Against the Operator

- **Status:** shipped (2026-07-10, spec v0.2.5)
- **Issue:** rad:11ae0ea
- **Affects:** chp-v0.2.md (new §12), chp-http-binding.md §3 (three routes), new `chain-witness` schema + vector; canonical bytes: **no changes to existing objects** (new statement kind; new derived digest `chp-store-head-v1`)

## Problem

Evidence is tamper-*evident*: each correlation is a hash chain, exports are
signed, task bundles prove causal closure. But signing happens at **export
time**, and the store is a SQLite file the host operator controls. Between
export moments, an operator (or an attacker with the host's key and
filesystem) can rewrite history wholesale — re-chain, re-sign, serve the new
story. The first question every auditor asks — *"what stops you editing the
database?"* — currently has the weak answer "export early." For a protocol
whose wedge is provability, that is the deepest remaining gap.

## Design

**Peers countersign each other's chain heads.** A witness statement is a
record the witnessed operator *cannot delete* — it lives with the witness.

**Store head (`chp-store-head-v1`).** Chains are per-correlation over one
global sequence, so the witnessable unit is a derived digest: for every
correlation, take its head `content_hash` at global sequence ≤ N; the store
head is `sha256` over the sorted `correlation_id\x00head_hash\n` lines.
Because chains are append-only and the sequence never rewinds, the head
**as-of any witnessed N is recomputable later** — that recomputability is the
whole mechanism: rewriting any event at sequence ≤ N changes some
correlation's head, and the recomputed root no longer matches what a peer
signed.

**Statement `kind:"chain-witness"`** — the fourth statement-family member:

```json
{
  "kind": "chain-witness", "host_id": "<witnessed>",
  "sequence": 1234, "store_head": "<hex64>",
  "witnessed_at": "…", "canonicalization": "chp-stable-v1",
  "witness": { "host_id": "…", "public_key": "…",
               "host_identity": { …attestation, anchors §3.1… } },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "…" }
}
```

The witness signs only the **root** — no correlation ids leak to peers.

**Exchange.** New authed routes: `GET /head` returns
`{host_id, sequence, store_head, at}` (authed — the sequence discloses
activity volume); `POST /witness` delivers a statement to the witnessed host,
which MUST verify the signature **and recompute its own head at that
sequence** before persisting; `GET /witnesses` (authed) serves received
statements. On receipt the witnessed host also snapshots its **leaves at N**
beside the statement (`~/.chp/witnesses/received.json`) — the signed root
makes the snapshot tamper-evident. The witness keeps every statement it
issued (`~/.chp/witnesses/issued/<host_id>.json`, rolling window) and stamps
`last_witness` in its mesh manifest. Witness records **never enter the
evidence store** — appending one would draw a sequence and move the very head
being witnessed.

**Retention coexistence (the crux).** Retention legally deletes whole
correlations (purge) and legally NULLs hashes (redaction) — old witnesses
must not scream "tampered" at lawful lifecycle operations. Verification
(`chp witness verify --store <db> <receipts>`) is per-leaf, using the
snapshot: head matches = **verified**; correlation absent = **purged**
(legal); head NULLed = **redacted** (legal — redaction can only NULL, never
forge a different valid hash); head *differs* = **TAMPERED**; a correlation
present in the store at sequence ≤ N but missing from the snapshot =
**TAMPERED** (inserted history). Honest lifecycle and malicious rewriting are
distinguishable, so no witness-expiry rules are needed.

**Cadence.** A new witness loop rides the gateway (opt-in
`gateway.witness_interval_s`, default off — the same pattern as the prober),
witnessing every mesh peer each tick. Any host MAY witness any peer; the
gateway is simply the natural carrier.

## Compatibility

Fully additive: no existing object changes, all published vectors
byte-identical (one NEW vector: `chain-witness.json`). A host that neither
issues nor accepts witnesses remains conformant at the export-signing floor —
witnessing upgrades the tier from tamper-evident to tamper-proof-against-
the-operator. Wire suite grows **18→19** ("witness round-trip": the runner
acts as witness — `/head` → `POST /witness` → `GET /witnesses`, sequence
monotonic across an invocation); store-head *recomputation* is proven by
reference tests and `chp witness verify`, not black-box (a runner cannot see
the store). Both implementations move: the TS host serves the three routes
with in-memory receipts; the SDK gains `buildChainWitness`/`verifyChainWitness`.

Deferred by design: witness-of-witness chains, cross-mesh (never-met)
witnessing, witness quorum policies, anchoring heads to external transparency
logs (Rekor et al. — the §9 interop doc's posture applies), and using
witnessed heads as a mandate-revocation freshness channel.

## Shipped as

- Spec: chp-v0.2.md **§12 Witnessing**; binding §3 route rows (`/head`,
  `POST /witness`, `GET /witnesses`); CHANGELOG **[0.2.5]**
- Vectors/Guards: `spec/test-vectors/chain-witness.json` (fixed-seed;
  vector doubles as an executable chp-store-head-v1 example) +
  `schemas/chain-witness.schema.json`; guards
  `chain_witness_vector_verifies` + `spec_defines_witnessing` (61
  alignment checks); wire suite **18→19** ("witness round-trip") — both
  reference hosts pass 19/19
- Implementations: Python `store.get_store_head(at_sequence)` +
  `signing.build/verify_chain_witness` + `witnessing.py` sidecars with
  leaves snapshots + `chp witness verify` per-leaf dispositions
  (verified/purged/redacted/TAMPERED; doctored snapshots flagged) +
  routes; `chp_host/witness.py` loop (`gateway.witness_interval_s`,
  default off) + mesh.json `last_witness`; TS `computeStoreHead`/
  `buildChainWitness`/`verifyChainWitness` + host routes (in-memory
  receipts) — cross-language head-scheme parity test included
- Refinement vs proposal: none — landed as designed (11 adversarial
  Python tests incl. direct SQLite rewrite, backdated insert, doctored
  snapshot)
