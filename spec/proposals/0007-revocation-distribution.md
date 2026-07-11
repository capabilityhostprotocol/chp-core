# 0007: Revocation Distribution — Withdrawing Authority Before Expiry

- **Status:** shipped (2026-07-10, spec v0.2.6)
- **Issue:** rad:eaf538b
- **Affects:** chp-v0.2.md §10 (revocation subsection), chp-http-binding.md (two new routes), `mandate-revocation` schema + vector (new); canonical bytes: **no existing object changes** (new `kind:"mandate-revocation"` statement; no new denial codes; no envelope changes)

## Problem

A mandate's only recovery today is its expiry: between issuance and
`valid_until`, a compromised or over-trusted delegate acts with full granted
authority and the principal has no protocol move — §10 explicitly deferred
"revocation lists... mirror §3.2 when demanded" (proposal 0002), and 0005
named "witnessed heads as a mandate-revocation freshness channel". The demand
arrived with mandates in live use (steward per-run mandates since v0.2.4):
short windows mitigate but do not remove the gap, and shortening windows
trades against issuance overhead. Key revocation half-exists: self-signed
statements in `revocations.json` reach only *resolving* verifiers via the
identity document — there is no route a peer can push to or pull from.

## Design

A **mandate revocation** is the fifth statement-family member (bundles §3,
provenance §9, mandates §10, chain-witness §12): the principal's signed
withdrawal of a mandate before its expiry.

```json
{
  "kind": "mandate-revocation", "mandate_id": "mnd_…",
  "revoked_at": "…", "reason": "…", "canonicalization": "chp-stable-v1",
  "principal": { "host_id": "…", "public_key": "…",
                 "host_identity": { …attestation, anchors §3.1… } },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "…" }
}
```

- Signature over the canonical header (`kind, mandate_id, revoked_at, reason,
  canonicalization`).
- **Issuer-only rule (the load-bearing decision)**: a revocation binds to a
  mandate by `mandate_id` AND by principal-key match. A verifier holding a
  mandate checks candidate revocations by verifying the revocation signature
  **against the mandate's own `principal.public_key`** — never against the
  statement's self-declared key, which would let anyone revoke anyone by
  naming a `mandate_id`. A statement signed by any other key is inert.
- **Enforcement**: pipeline gate 5 consults the host's local revocation set;
  a revoked mandate is the existing PROCESSED denial `mandate_invalid`
  (`not_revoked` joins the named mandate checks). **No new denial code.**
  Revocation is not a validity-window edit: once known, the mandate is
  invalid at all times.
- **Distribution is push + pull, host-local**: `POST /revocations` (authed)
  delivers a statement; the receiving host MUST verify it self-consistently
  (signature, attestation) before persisting — an unverifiable statement is
  refused, never stored. `GET /revocations` (authed) serves what the host
  holds: `{keys: [...§3.2 self-signed key revocations...], mandates: [...]}` —
  key revocations thereby gain their first standalone wire surface (offline
  verifiers no longer depend on resolving the identity document). Received
  mandate revocations persist in sidecar storage (`~/.chp/revocations/`, the
  witnessing precedent) — NOT in `revocations.json`, which holds the host's
  own key revocations and is served verbatim in the identity document.
- **Best-effort propagation, deliberate floor**: the principal (reference:
  `chp mandate revoke --push <host>`) pushes to the hosts it knows honor the
  mandate. There is no gossip, no global list, no freshness proof — a host
  that never receives the revocation keeps honoring the mandate until expiry,
  which is exactly the pre-0007 posture. Expiry remains the backstop;
  revocation upgrades recovery from "wait out the window" to "one authed POST
  per enforcing host".

## Compatibility

Fully additive: hosts that ignore revocations remain conformant at the
expiry-only floor; the new wire check is what claims revocation support. No
canonical-byte change to any existing object; all published vectors
byte-identical; `mandate-revocation.json` lands with the implementation.
Wire conformance grows 19→20.

Deferred by design: key-revocation *push* (keys stay self-serve via identity
doc + the new GET), gossip/relay propagation, revocation freshness proofs
(the 0005 witnessed-heads idea — a host proving it knew the newest set),
sub-delegation-chain revocation (needs sub-delegation first), and
`max_invocations` (unchanged from 0002).

## Shipped as

- Spec: chp-v0.2.md **§10 "Revocation"** (issuer-only rule normative);
  http-binding route rows `GET /revocations` + `POST /revocations`
  (400 `invalid_revocation`); CHANGELOG **[0.2.6]**
- Vectors: `spec/test-vectors/mandate-revocation.json` (fixed-seed, revokes
  the mandate vector's `mnd_fixture0001` — the pair proves the binding);
  `schemas/mandate-revocation.schema.json`; all pre-existing vectors
  byte-identical; `verify.mjs` branch
- Guards: `spec_defines_revocation` + `mandate_revocation_vector_verifies`
  (alignment 61→63); wire suite **19→20** (`check_mandate_revocation`:
  revoke-then-deny round-trip, tampered refused 400, forged/impostor-key
  statement provably inert — both reference hosts 20/20)
- Implementations: Python `signing.build_mandate_revocation`/
  `verify_mandate_revocation` + `verify_mandate(revocations=)` +
  `revocations.py` sidecar (`CHP_REVOCATION_DIR`) + gate-5 wiring + routes +
  `RemoteCapabilityHost.revocations()/post_revocation()` + `chp mandate
  revoke [--push]`; TS `buildMandateRevocation`/`verifyMandateRevocation` +
  `verifyMandate({revocations})` (chp-sdk, cross-verified against the
  Python-signed vector pair) + host gate + in-memory routes
- Refinement vs proposal: none — landed as designed; the named deferrals
  (gossip, freshness proofs, key-revocation push, sub-delegation-chain
  revocation) stayed deferred
