# 0002: Signed Mandates — Delegated Authority on the Wire

- **Status:** shipped (2026-07-09, spec v0.2.3)
- **Issue:** rad:5c049b5
- **Affects:** chp-v0.2.md (new §10), chp-http-binding.md §2, chp-invocation-pipeline.md, chp-governance-v0.2.md §2 (denial code), `invocation-envelope` schema (additive optional field); canonical bytes: **no existing object changes** (new `kind:"mandate"` statement; the envelope field is omit-when-absent)

## Problem

Cross-host authority today is a static pre-shared API key: host B's environment
maps A's key to a caller name and scope. The credential is provisioned
out-of-band per pair, has no expiry, is revocable only by editing B's env, and
is unverifiable by any third party. "Agent A authorized this specific work on
B" cannot be proven from the evidence — only "someone holding A's key called B".
Meanwhile the delegation *lifecycle* vocabulary (`delegation_*` events) is
reserved but dormant — structure ahead of demand would repeat the mistake this
proposal avoids: the demanded piece is the **authority object**, not the
lifecycle.

## Design

A **mandate** is the third member of the statement family (signed bundles §3,
adapter provenance §9): a canonical, signed, expiring, capability-scoped
authority object.

```json
{
  "kind": "mandate", "mandate_id": "…",
  "delegate_id": "steward-x",
  "scope": ["demo.echo", "chp.adapters.audit.*"],
  "valid_from": "…", "valid_until": "…",
  "created_at": "…", "canonicalization": "chp-stable-v1",
  "principal": { "host_id": "…", "public_key": "…",
                 "host_identity": { …attestation, anchors §3.1… },
                 "key_history": [ …§3.2, omit-when-empty… ] },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "…" }
}
```

- Signature over the canonical header (`kind, mandate_id, delegate_id, scope,
  valid_from, valid_until, created_at, canonicalization`). Scope uses the
  binding-§2 grammar (exact capability id or trailing-`*`).
- **Presentation**: `InvocationEnvelope.mandate` (optional, additive). The
  delegate host verifies offline — signature, principal attestation
  (binding + temporal), DID anchor when present, validity window at
  invocation time, and that the invoked capability is in scope.
- **Subject binding**: a valid mandate binds the evidence subject to
  `{id: delegate_id, type: "mandate", verified: true, mandate_id,
  principal: <principal host_id>}` — "B acted under A's mandate M" lands in
  the signed chain with no new event types. Transport auth (§2) still gates
  the connection; a mandate narrows/attributes, it never bypasses.
- **Denials**: an invalid/expired/tampered/wrong-delegate mandate is a
  PROCESSED denial with the new reserved code `mandate_invalid`; an invocation
  outside a valid mandate's scope is `policy_blocked` (existing semantics).
- **Principal trust**: attestation verifies offline; anchors answer "whose
  authority"; a verifier MAY require a mesh-pinned principal key.

## Compatibility

Fully additive: an envelope without a mandate behaves exactly as today; a host
that ignores mandates remains conformant at the prior tier (the new wire check
is what claims mandate support). No canonical-byte change to any existing
object. Byte-compat gate: all published vectors unchanged; `mandate.json`
lands with the implementation. Wire conformance grows 17→18.

Deferred by design: `max_invocations` (delegate-side counting state), mandate
revocation lists (mirror §3.2 when demanded), sub-delegation/chaining, and the
delegation lifecycle promotion itself (mandates are its foundation).

## Shipped as

- Spec: chp-v0.2.md **§10**; pipeline **gate 5** (gates renumbered 10→11,
  editorial); http-binding §2 mandate paragraph; governance §2 reserved code
  **`mandate_invalid`** (10 codes); CHANGELOG **[0.2.3]**
- Vectors: `spec/test-vectors/mandate.json` (fixed-seed, byte-stable);
  `schemas/mandate.schema.json`; all pre-existing vectors byte-identical
- Guards: `mandate_vector_verifies` (alignment, 57 checks); wire suite
  **17→18** (`check_mandate_gate`: never-met principal, valid / out-of-scope /
  expired / tampered — both reference hosts pass 18/18)
- Implementations: Python `signing.build_mandate`/`verify_mandate` +
  `host.py` gate + `RemoteCapabilityHost.ainvoke(mandate=)` + `chp mandate
  issue|verify` + verify-evidence dispatch; TS `verifyMandate`/`scopeAllows`
  (chp-sdk) + `host.ts` gate + client `mandate` opt + `verify.mjs` branch
- Refinement vs proposal: none — landed as designed; `max_invocations`
  stayed deferred as named
