# 0037: Resumable Invocation + Provable Approval Grants

- **Status:** shipped (spec v0.9.1, chp-core 0.47.0, npm alpha.41)
- **Issue:** rad:eb5ee723
- **Affects:** chp-v0.2.md §19 (new) + a new `schemas/chp-approval-grant.schema.json` +
  the optional `approval_ref` envelope field + a new `approval_grant_verified` evidence
  type. **No new reserved denial code** (the gate still denies the existing
  `approval_required`). **Additive:** an envelope without `approval_ref` is byte-identical.
  Spec **v0.9.0 → v0.9.1**. M2 / GAP 4a (PUBLIC half of the crossover — the private
  durable approval-queue service is arc 4b in `chp-platform`, per ADR-0002/0003).

## Problem

A capability with `autonomy.tier == "approval_required"` denies `approval_required`
**unconditionally** — the gate never consults an approval, and `grant_approval` is a bare,
**unsigned** evidence emitter (`decided_by` free-text) with no `approval_id` and **no
re-drive**. Worse, the idempotency gate (§13) caches that `approval_required` denial under
the `invocation_id`, so resuming needs a *fresh* id — which forfeits duplicate-execution
protection across the approve→execute boundary. Approval is therefore advisory,
host-asserted, and un-resumable. GAP 4.

## Design

**Provable grant — `chp-approval-grant-v1`.** An approver's ed25519-signed record modelled
on `disclosure-receipt`: header `(kind, approval_id, invocation_id, decision, approver,
valid_until, payload_commitment, canonicalization)`, a self-attested `approver_identity`,
and a `signature`. `verify_approval_grant(grant, *, at_time, expected_approver_key=None)`
checks structure + the approver signature over the canonical header + `binds_signer`
(`approver == signature.key_id`) + temporal (not expired) + an optional pinned approver key.
No new crypto — reuses `_canon`/`_sign`/`_verify_sig`. A third party thus verifies offline
that an approver authorized this exact invocation + payload.

**`approval_ref` envelope field.** Optional, omit-when-absent (byte-identical when unused),
like `mandate`/`actor`. Carries the grant the caller presents to resume.

**Resume, executed exactly once.** Two gates cooperate, keeping **one `invocation_id`**:
- The **autonomy gate** (gate 8) accepts the invocation when `approval_ref` presents a grant
  that verifies AND matches this `invocation_id` AND `payload_commitment` AND
  `decision == "granted"` — emitting `approval_grant_verified`; else it denies
  `approval_required` as before.
- The **replay gate** (gate 0) would otherwise replay the cached `approval_required` denial;
  when a valid grant is presented it instead **deletes** the stale denial row (the cache is
  otherwise first-writer-wins) and falls through to execute. The terminal result records
  under the same id, so a later retry replays the *result*. The handler runs **exactly once**.

**Payload binding.** The grant commits `payload_commitment = sha256(chp-stable-v1(payload))`;
both gates require the envelope's payload commitment to match. Approve payload A, resume with
payload B → mismatch → still denied. This closes the substitution hole the id-keyed result
cache would otherwise leave open.

## Compatibility

Additive and byte-identical when unused. No wire break, no new denial code. Three
implementations (Python, TS host, stdlib `verify.mjs` + the SDK `verifyApprovalGrant`) agree
via `spec/test-vectors/approval-grant.json`. The richer decision states
(`modify_and_approve` / `request_more_context` / `delegate` / `escalate` / `expire`) and the
durable approval-queue **service** that produces grants live in the private `chp-platform`
repo (arc 4b) — out of scope for the wire.

## Shipped as

- **Spec:** chp-v0.2.md §19.
- **Signing:** `build_approval_grant` + `verify_approval_grant` (`signing.py`); SDK
  `verifyApprovalGrant` (`verify.ts`).
- **Schema:** `schemas/chp-approval-grant.schema.json`; `approval_ref` on the envelope;
  `approval_grant_verified` evidence type.
- **Host:** grant-aware gate 8 + resume-aware gate 0 + `_valid_approval_for` + a
  `store.delete_result` supersede path (Python), mirrored in `chp-host-ts`.
- **Vectors/guards:** `approval-grant.json` (valid + expired + tampered) + `verify.mjs`
  branch; `spec_defines_approval_grant` + `approval_grant_vector_verifies`.
- **Tests:** `test_approval_grant.py` (exactly-once, payload-swap rejected, expiry,
  wrong-invocation, no-grant, omit-when-absent); SDK `vectors.test.ts` case.
- **ADR:** `docs/engineering/adr/0003-resumable-invocation.md`.
