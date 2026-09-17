# 0053: Signed introduction batches (cryptographic issuer verification)

- **Status:** shipped
- **Issue:** rad:fce30b1
- **Affects:** chp-server introduction-batch contract (additive, optional field); NO
  invocation-wire change (introduction is the administration plane, INTRO-039). Reuses
  the proposal-0050 signed-assertion primitive; no new canonical-bytes surface.

## Problem

INTRO-018 requires a source/issuer trust policy to be evaluated before candidate facts
become active. The first layer (proposal-gate, shipped) keys trust on a configured
`source_id` string — sufficient for the admin-plane model where the operator configures
sources, but a string is not a cryptographic identity. For a stronger posture (a source
whose identity is a KEY, verifiable independently of a mutable configuration string),
the coordinator needs to verify that a batch was actually issued by a trusted key and
commits to exactly the content presented.

## Design

**Signed batch (additive, optional).** A source MAY attach a `source_attestation` to its
batch — a proposal-0050 signed assertion:

```
source_attestation = sign_assertion(issuer_key, {
    id:         "introbatch:<source_id>:<generation>",
    claim_type: "capability_introduction_batch",
    issuer:     <source_id>,
    value:      introduction_batch_commitment(batch),   # binds the content
})
```

`introduction_batch_commitment(batch)` is a stable sha256 over `{source_id, generation,
members}` where `members` is the sorted `[candidate_id, canonical_digest]` of every
candidate — so the signature commits to exactly this batch's introduced content.

**Verification gate (before activation).** A coordinator configured with a cryptographic
trust policy (`SourceTrustPolicy(trusted_key_ids=…)` or `require_signed=True`) refuses a
batch at `stage()` — before any activation — unless ALL hold:

1. a `source_attestation` is present;
2. its ed25519 signature verifies (`verify_assertion_signature`, proposal 0050) —
   integrity + attribution, `binds_signer`;
3. the signer `key_id` is in `trusted_key_ids` (the trusted issuers);
4. the attestation's `value` equals the recomputed `introduction_batch_commitment` —
   the signature commits to THIS content (a signature lifted onto tampered candidates
   fails here).

No cryptographic policy configured → the string-`source_id` gate (first layer) applies
unchanged. This layers strictly on top; it never weakens the existing gate.

## Compatibility

- Additive: `source_attestation` is an optional batch field (introduction-batch schema
  updated, `additionalProperties` still false but the field is now named). A coordinator
  with no cryptographic policy ignores it — today's behavior.
- No invocation-wire or canonical-invocation-bytes change; introduction is admin-plane.
- Trust acceptance stays a relying-policy decision (CHP-VER-011): a valid signature
  proves attribution/integrity, never truth — the operator's `trusted_key_ids` is the
  acceptance decision. Anchoring a key to an external trust root (domain/DID anchor,
  spec §3) for a never-configured issuer is the next layer, reusing `verify_attestation`.

## Shipped as

- Implementation: chp-server `SourceTrustPolicy(trusted_key_ids, require_signed)`,
  `introduction_batch_commitment`, `sign_introduction_batch`, and the `stage()`
  verification gate. Reuses chp-core `sign_assertion` / `verify_assertion_signature`.
- Contract: contracts/introduction-batch.schema.json (`source_attestation`).
- Tests: test_introduction.py::test_intro_018_crypto_signed_batch_from_trusted_issuer_activates
  + ::test_intro_018_crypto_untrusted_issuer_and_tamper_refused (unsigned refused, trusted
  activates, untrusted key refused, tampered content refused).
- Follow-up: anchor-rooted issuer trust (never-configured sources) via attestation anchors.
