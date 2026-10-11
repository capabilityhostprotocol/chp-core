"""Activation-effect authority gate (M1.3, ADR-002) — DRAFT, pending independent RE-review.

The destination host independently authorizes a privileged ACTIVATION EFFECT (CONNECT
bind / DEPLOY provision / INSTANTIATE run) as an authority DISTINCT from invocation
authority: holding invocation authority, being registered, or being connected is NOT
sufficient. The authority is a scoped, bounded, plan-digest-bound, approver-signed grant.

This is the standalone, PURE authorization logic + the reserved denial code. It is
deliberately NOT wired into the live invocation pipeline (``host.py:_prepare`` /
``_valid_approval_for`` — impact analysis: CRITICAL hot path), and NOT exported from the
public ``chp_core`` surface. It reuses ``signing.verify_approval_grant`` (which, since
rad:0ae5fec, binds the approver identity to key material) for signature/identity/temporal.

Hardened across two independent-review rounds (rad:3979672):
  * FAIL CLOSED — every protective input is REQUIRED; a missing/None/wrong-typed one DENIES
    (incl. a non-str actor_key_id). The decision body is wrapped so a malformed input that would
    otherwise raise an ordinary Exception DENIES instead (review round-2 F2). (BaseException —
    e.g. KeyboardInterrupt — is intentionally not swallowed; inputs are host-constructed, not
    hostile Python objects.)
  * DISTINCT authority — the grant must bind the plan via ``action_digest`` (NOT the
    ``payload_commitment`` an invocation-resume grant also carries).
  * publisher trust is driven by the effect KIND, not an opt-in flag: DEPLOY/INSTANTIATE
    (artifact-installing) REQUIRE a trusted publisher; a mis-wired caller can no longer skip
    it (review round-2 F1). An unknown kind fails closed.
  * self-approval is KEY-to-KEY (approver key_id vs the actor's key_id).
  * single-use is mandatory + honors signed ``max_attempts``; readiness must be exactly
    ``True`` (a truthy non-bool is rejected, review round-2 F3).
  * all activation-specific refusals use the reserved ``activation_not_authorized``; host
    policy and publisher-trust reuse ``policy_blocked`` / ``approval_required``.

Wiring plan (for the reviewer), still REQUIRED before this is safe end-to-end:
  1. A pipeline step in ``_prepare`` that engages ONLY on an activation effect, performs the
     HOST-side ATOMIC check-and-consume of ``approval_id`` (a uniqueness constraint / lock —
     the pure gate only does set-membership, so it cannot prevent a concurrent double-spend),
     then calls this gate.
  2. The step MUST treat ANY exception from the gate as a denial (defence in depth, though the
     gate is already wrapped to never raise).

WIRED (M1.3, rad:a9a3b68): host._prepare engages this gate when an invocation carries an
activation context (envelope.activation_ref), sourcing trust/scope/consumed state host-side and
performing the ATOMIC approval_id consume (activation_consume.ActivationConsumeStore). The three
gate review rounds passed (no known bypass), ADR-002 Class-C sign-off was granted, and the WIRING
got its own independent review = SAFE TO LAND (F-1 double-spend / F-2 fail-unsafe-raise / F-3
self-approval closed; follow-on a419e02 = ingress subject.verified trust, fail-closed over HTTP
today). Gate stays de-exported from the public chp_core surface (internal use only).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .signing import verify_approval_grant
from .types import DenialReason

# The reserved denial code for a refused activation EFFECT (registered in
# DenialReason.RESERVED_CODES + denial-reason schema + spec). Host policy and publisher-trust
# reuse the existing reserved policy_blocked / approval_required.
ACTIVATION_NOT_AUTHORIZED = "activation_not_authorized"

# Activation strategies. DEPLOY/INSTANTIATE install an artifact onto the host and therefore
# REQUIRE a trusted publisher; CONNECT binds an existing endpoint (no artifact).
_KNOWN_STRATEGIES = frozenset({"CONNECT", "DEPLOY", "INSTANTIATE"})
_ARTIFACT_STRATEGIES = frozenset({"DEPLOY", "INSTANTIATE"})


@dataclass(frozen=True)
class ActivationAuthorization:
    """Result of the activation-effect gate. ``authorized`` True → the effect may proceed;
    otherwise ``denial`` carries the reason (first-class evidence, emitted as
    ``activation_denied``)."""

    authorized: bool
    denial: DenialReason | None = None


def _deny(code: str, message: str, *, invariant_id: str | None = None,
          retryable: bool = False) -> ActivationAuthorization:
    return ActivationAuthorization(
        False, DenialReason(code=code, message=message, invariant_id=invariant_id, retryable=retryable))


def authorize_activation_effect(
    *,
    grant: dict | None,
    plan_digest: str,
    effect_kind: str,
    actor_key_id: str,
    at_time: str,
    expected_audience: str,
    trusted_approver_keys: Iterable[str],
    consumed_approval_ids: Iterable[str],
    readiness_eligible: bool,
    host_policy_denied: bool = False,
    publisher_fingerprint: str | None = None,
    trusted_publisher_fingerprints: Iterable[str] | None = None,
) -> ActivationAuthorization:
    """Authorize (or refuse) a privileged activation effect. PURE and FAIL-CLOSED: all state is
    passed in, every protective input is required, and ANY malformed input or internal error
    DENIES (the body never raises). Checks are ordered fail-closed, most-fundamental first.

    ``effect_kind`` is the strategy (CONNECT / DEPLOY / INSTANTIATE); DEPLOY/INSTANTIATE require
    a trusted publisher (derived here, not caller-supplied). ``actor_key_id`` is the requesting
    actor's signing key_id (key-to-key self-approval check). Tenant scope is enforced via
    ``expected_audience`` vs the grant's signed ``audience``.

    NEG-ACT-* refer to the negative-case catalog. Timeout-after-effect (NEG-ACT-009) is a
    downstream reconciliation concern, not an authorization decision, and is not handled here."""
    try:
        return _authorize(
            grant=grant, plan_digest=plan_digest, effect_kind=effect_kind,
            actor_key_id=actor_key_id, at_time=at_time, expected_audience=expected_audience,
            trusted_approver_keys=trusted_approver_keys, consumed_approval_ids=consumed_approval_ids,
            readiness_eligible=readiness_eligible, host_policy_denied=host_policy_denied,
            publisher_fingerprint=publisher_fingerprint,
            trusted_publisher_fingerprints=trusted_publisher_fingerprints)
    except Exception:  # noqa: BLE001 — a security gate must DENY on any malformed input, never raise (F2)
        return _deny(ACTIVATION_NOT_AUTHORIZED,
                     "activation authorization failed closed on malformed input", invariant_id="ADR-002")


def _authorize(
    *, grant, plan_digest, effect_kind, actor_key_id, at_time, expected_audience,
    trusted_approver_keys, consumed_approval_ids, readiness_eligible, host_policy_denied,
    publisher_fingerprint, trusted_publisher_fingerprints,
) -> ActivationAuthorization:
    # NEG-ACT-008 — the destination host's own policy dominates. Short-circuits everything.
    if host_policy_denied:
        return _deny("policy_blocked", "the destination host policy refused the activation effect")

    # NEG-ACT-001 / NEG-ACT-002 — no grant (or a malformed non-dict one). Invocation authority,
    # registration, and connectivity do NOT imply activation permission. Shape-guarded (MEDIUM-8).
    if not grant or not isinstance(grant, dict):
        return _deny(ACTIVATION_NOT_AUTHORIZED,
                     "no activation grant presented; invocation/registration is not activation authority",
                     invariant_id="ADR-002")

    # FAIL CLOSED on incomplete authorization inputs (HIGH-2): deny, never skip a check. readiness
    # must be exactly True — a truthy non-bool (e.g. the string "false") is rejected (F3).
    # actor_key_id must be a non-empty STRING: a truthy non-string (e.g. bytes/object) could never
    # equal the str `approver`, silently defeating the self-approval check below — so type-guard it here
    # (final RE-review finding; a malformed protective input must DENY, not slip through).
    if (expected_audience is None or trusted_approver_keys is None
            or consumed_approval_ids is None or readiness_eligible is None
            or not isinstance(actor_key_id, str) or not actor_key_id):
        return _deny(ACTIVATION_NOT_AUTHORIZED,
                     "activation authorization inputs are incomplete; failing closed", invariant_id="ADR-002")

    # F1 — publisher trust is derived from the effect KIND, not a caller flag. An unknown strategy
    # fails closed (we cannot classify its supply-chain risk).
    if effect_kind not in _KNOWN_STRATEGIES:
        return _deny(ACTIVATION_NOT_AUTHORIZED, f"unknown activation strategy {effect_kind!r}; failing closed")
    requires_publisher = effect_kind in _ARTIFACT_STRATEGIES

    if grant.get("decision") != "granted":
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the activation grant is not a 'granted' decision")

    # NEG-ACT-004 (expired) + signature/identity/key-binding — the one offline verifier.
    verification = verify_approval_grant(grant, at_time=at_time)
    if not verification.valid:
        if not (bool(grant.get("valid_until")) and at_time <= str(grant.get("valid_until"))):
            return _deny(ACTIVATION_NOT_AUTHORIZED, "the activation grant has expired", retryable=True)
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the activation grant failed verification (signature/identity)")

    # NEG-ACT-012 — approver key must be currently trusted (not revoked). REQUIRED set.
    approver = str(grant.get("approver") or "")
    if approver not in set(trusted_approver_keys):
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the grant's approver key is not trusted (revoked or unknown)",
                     invariant_id="ADR-002")

    # NEG-ACT-011 — no self-approval: approver KEY must differ from the actor's KEY.
    if approver and approver == actor_key_id:
        return _deny(ACTIVATION_NOT_AUTHORIZED, "self-approval is not permitted; the approver must be out-of-band")

    # NEG-ACT-003 + distinct authority (MEDIUM-5) — bind the plan via action_digest only.
    bound_digest = grant.get("action_digest")
    if not bound_digest or bound_digest != plan_digest:
        return _deny(ACTIVATION_NOT_AUTHORIZED,
                     "the grant is not bound to this activation plan via action_digest")

    # NEG-ACT-006 — tenant/scope binding, via the grant's signed audience. REQUIRED.
    if grant.get("audience") != expected_audience:
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the grant was issued for a different tenant/scope")

    # NEG-ACT-005 / NEG-ACT-013 — single-use. REQUIRED consumed set + signed budget. The HOST does
    # the ATOMIC check-and-consume keyed on approval_id at wire time; the pure gate checks membership.
    approval_id = grant.get("approval_id")
    if not approval_id:
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the grant has no approval_id; single-use cannot be enforced")
    if approval_id in set(consumed_approval_ids):
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the activation grant has already been consumed (replay)")
    max_attempts = grant.get("max_attempts")
    if max_attempts is not None and int(max_attempts) < 1:
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the grant's single-use budget is exhausted")

    # NEG-ACT-010 — readiness must be exactly True (F3: reject a truthy non-bool).
    if readiness_eligible is not True:
        return _deny(ACTIVATION_NOT_AUTHORIZED, "the implementation is not eligible (readiness incomplete/ineligible)",
                     invariant_id="CHP-RDY-007")

    # NEG-ACT-007 — artifact strategies (DEPLOY/INSTANTIATE) require a trusted publisher; an absent
    # or untrusted one needs explicit human approval (REQUIRES_APPROVAL), as observed live.
    if requires_publisher or publisher_fingerprint is not None:
        trusted_pubs = set(trusted_publisher_fingerprints or ())
        if publisher_fingerprint is None or publisher_fingerprint not in trusted_pubs:
            return _deny("approval_required", "the artifact publisher is not yet trusted; human approval required",
                         retryable=True)

    return ActivationAuthorization(True, None)
