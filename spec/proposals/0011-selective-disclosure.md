# 0011: Selective Disclosure — Withholdable Payloads via `chp-event-hash-v2`

- **Status:** shipped (2026-07-11, spec v0.3.0)
- **Issue:** rad:b3d5b76
- **Affects:** chp-v0.2.md §2 (a second content-hash scheme `chp-event-hash-v2`) + new **§14 "Selective disclosure"**; `evidence-event` schema (two optional additive fields); CHANGELOG **[0.3.0]**. Canonical bytes: **v1 events unchanged** (`chp-event-hash-v2` is opt-in per event, marked by a `hash_scheme` field absent on every existing event) — the published `event.json` / `signed-bundle.json` vectors are byte-identical. First **canon evolution** (a new hashing rule) → spec **v0.3.0**.

## Problem

Evidence bundles are **all-or-nothing**. `content_hash` (chp-v0.2.md §2) is a
SHA-256 over the event's stable fields *including the raw `payload` inline*, and
`verify_bundle` re-derives that hash to verify — so a verifier needs every
payload to check the chain. An auditor who should see only a correlation's
*control flow* ("was this invocation denied? by which policy?") cannot be shown
the bundle without also being handed the payloads — customer data, secrets,
other tenants' inputs in a shared store. The bundle proves too much or nothing.

## Design

Commit to the payload by **hash**, not by value, so it can be dropped without
breaking verification. A new per-event content-hash scheme
**`chp-event-hash-v2`** hashes a `payload_commitment` in place of the inline
payload; a bundle can then **withhold** a payload (ship the commitment, drop the
value) and still verify against the same signed root.

- **`chp-event-hash-v2`** — the `content_hash` stable object is identical to
  `chp-stable-v1`'s except the `"payload": <payload>` member is replaced by
  `"payload_commitment": sha256(chp-stable-v1(payload))`. An event self-describes
  its scheme with a `hash_scheme: "chp-event-hash-v2"` field; **absent means v1**
  (the legacy inline-payload rule, byte-identical). `payload_commitment` is a
  commitment over the payload canonicalized with the *same* `chp-stable-v1`
  rules (the empty payload is the explicit object `{}` — this pins the one
  cross-impl divergence where a missing payload defaulted to `null` in one impl
  and `{}` in another).
- **Withholding (non-destructive).** A *disclosure-minimized* bundle replaces a
  v2 event's `payload` with the marker `{"chp_withheld": true}` and keeps its
  `payload_commitment` and `content_hash`. The root hash and the signature are
  **untouched** (both build only on `content_hash`), so the *original* signature
  still validates the minimized bundle — no re-signing, no store mutation.
- **Verification.** For a v2 event `verify_bundle` recomputes `content_hash`
  from the stable fields + `payload_commitment` (the raw payload is not needed —
  a withheld event verifies). If the event still carries a real `payload`
  (disclosed), the verifier *additionally* asserts
  `sha256(chp-stable-v1(payload)) == payload_commitment`, binding the disclosed
  value to what was signed. v1 events are unchanged (payload required).
- **Forward-only.** Hosts at 0.19+ stamp **new** events `chp-event-hash-v2`;
  existing events stay v1 and keep their exact hashes — the live mesh (chains,
  witnessed heads, signed exports, vectors) is preserved. A chain may mix v1 and
  v2 events; each self-describes and `prev_hash` links across schemes normally.

**This is NOT retention redaction.** §4/§12 *redaction* destroys a stored
payload and NULLs its `content_hash` (the event becomes `unverified`); *purge*
deletes whole correlations. Selective disclosure never touches the store, never
NULLs a hash, and never forges one — it is a verifiable, reversible *view* of an
intact signed bundle. The two mechanisms and their vocabularies stay disjoint
("withhold"/"minimize" here; "redact"/"purge" there).

## Compatibility

`hash_scheme` and `payload_commitment` are new optional event fields, absent on
every v1 event, so existing events, chains, store heads, witnessed receipts,
signed bundles, and the published vectors are **byte-identical**. A pre-0011
verifier rejects a withheld v2 bundle (it cannot recompute the hash without the
payload) — which is correct: withholding is a v0.3 capability. Bundle
`protocol_version` becomes `"0.3"` on 0.19 hosts, but `verify_bundle` branches on
the **per-event `hash_scheme`**, so a mixed bundle verifies regardless. No new
denial code, no new evidence type, no store event — withholding is a bundle
transform and a verify-tolerant property. Wire conformance grows by one check.

Deferred by design: per-field / sub-payload Merkle commitments (withhold *part*
of a payload); retroactive v1→v2 (old events stay non-withholdable);
withholding non-payload stable fields; *encrypting* (rather than dropping) a
withheld payload; disclosure receipts (proving what was disclosed to whom).

## Shipped as

- Spec: chp-v0.2.md **§2** (registers `chp-event-hash-v2` + the `hash_scheme`
  field) + new **§14 "Selective Disclosure"**; status line **v0.3.0**;
  CHANGELOG **[0.3.0]**; `evidence-event.schema.json` gains optional
  `hash_scheme` (`const`) + `payload_commitment`
- Bytes: existing vectors byte-identical (v1 has no `hash_scheme`); new
  `event-hash-v2.json` + `bundle-withheld.json`; no new statement kind, denial
  code, or evidence type; no store schema change (the marker rides in
  `event_json`)
- Guards: `spec_defines_selective_disclosure` + `event_hash_v2_vector_verifies`
  (alignment 68→70); wire suite **24→25** (`check_selective_disclosure`: a
  served host emits v2, a withheld export verifies against the unchanged signed
  root, a tampered-disclosed payload is refused; both reference hosts)
- Implementations: Python `_payload_commitment` + `_compute_event_hash` scheme
  branch + `emit_evidence` v2 stamp + `verify_bundle` v2 path (commitment bind +
  withhold tolerance) + `withhold_payloads` + `chp bundle minimize`/`verify`;
  TS `payloadCommitment` + `contentHash` v2 + `verifyBundle` payload-commitment
  check + `withholdPayloads` + chp-host-ts v2 emission (cross-verified against
  the Python-signed `bundle-withheld.json`); reference `verify.mjs` v2 branch
- Refinement vs proposal: no store schema change was needed — the `hash_scheme`
  / `payload_commitment` marker rides in the serialized `event_json`, so export
  and verify already see it (the plan's `user_version` bump was dropped);
  emission defaults to v2 (evidence born withholdable). Deferrals stayed named
  (per-field Merkle, retroactive v1→v2, non-payload fields, encryption,
  disclosure receipts).
