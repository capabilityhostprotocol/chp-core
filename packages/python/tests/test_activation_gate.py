"""Activation-effect authority gate (M1.3, ADR-002) — the negative-case conformance vectors
from docs/.../tests/ACTIVATION-GATE-NEGATIVE-CASES.md, the authorized path, and the
independent-review must-fixes across both rounds (rad:3979672): fail-closed inputs (None AND
malformed), action_digest-bound authority, key-to-key self-approval, mandatory single-use,
reserved denial code, effect-kind-derived publisher trust, strict bool readiness.

DRAFT gate (not wired into the pipeline); these pin the pure authorization logic the
independent RE-review validates.
"""
from __future__ import annotations

import pytest

from chp_core import signing
from chp_core.activation_gate import ACTIVATION_NOT_AUTHORIZED, authorize_activation_effect

PLAN = "sha256:" + "a" * 64
OTHER_PLAN = "sha256:" + "b" * 64
AT = "2026-10-10T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"
AUD = "acme:owned-host-1"
ACTOR_KEY = "actor-key-x"  # distinct from the approver key (out-of-band approver)


@pytest.fixture(scope="module")
def approver(tmp_path_factory):
    return signing.generate_keypair(tmp_path_factory.mktemp("approver"))


@pytest.fixture
def ctx(approver):
    """Default authorized context + a grant factory; each test mutates one axis.
    Default effect_kind=CONNECT (no artifact ⇒ no publisher needed) so the authorized path is clean."""
    def grant(**over):
        kw = dict(invocation_id="inv1", payload_commitment=PLAN, approval_id="ap1",
                  valid_until=FUTURE, action_digest=PLAN, audience=AUD, max_attempts=1)
        kw.update(over)
        return signing.build_approval_grant(approver, **kw)

    def authorize(**over):
        kw = dict(grant=grant(), plan_digest=PLAN, effect_kind="CONNECT", actor_key_id=ACTOR_KEY,
                  at_time=AT, expected_audience=AUD, trusted_approver_keys={approver.key_id},
                  consumed_approval_ids=set(), readiness_eligible=True)
        kw.update(over)
        return authorize_activation_effect(**kw)

    return {"grant": grant, "authorize": authorize, "approver": approver}


def test_authorized_path(ctx):
    auth = ctx["authorize"]()
    assert auth.authorized is True and auth.denial is None


def test_neg001_002_no_grant_is_not_authorization(ctx):
    auth = ctx["authorize"](grant=None)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_malformed_grant_shape_fails_closed(ctx):
    auth = ctx["authorize"](grant=["not", "a", "dict"])
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_neg003_plan_digest_mismatch(ctx):
    auth = ctx["authorize"](plan_digest=OTHER_PLAN)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_action_digest_required__payload_commitment_alone_rejected(ctx):
    g = ctx["grant"](action_digest=None)  # build_approval_grant omits a None field
    assert "action_digest" not in g and g["payload_commitment"] == PLAN
    auth = ctx["authorize"](grant=g)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_neg004_expired_grant(ctx):
    auth = ctx["authorize"](grant=ctx["grant"](valid_until=PAST))
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED
    assert auth.denial.retryable is True and "expired" in auth.denial.message


def test_neg005_replayed_grant(ctx):
    auth = ctx["authorize"](consumed_approval_ids={"ap1"})
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED
    assert "consumed" in auth.denial.message


def test_neg006_cross_tenant(ctx):
    auth = ctx["authorize"](expected_audience="other-tenant:host")
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_neg008_host_policy_rejection(ctx):
    auth = ctx["authorize"](host_policy_denied=True)
    assert not auth.authorized and auth.denial.code == "policy_blocked"


def test_neg010_unknown_compat_ineligible(ctx):
    auth = ctx["authorize"](readiness_eligible=False)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED
    assert auth.denial.invariant_id == "CHP-RDY-007"


def test_neg011_self_approval_denied_by_key(ctx):
    auth = ctx["authorize"](actor_key_id=ctx["approver"].key_id)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED
    assert "self-approval" in auth.denial.message


def test_neg012_revoked_or_untrusted_approver(ctx):
    auth = ctx["authorize"](trusted_approver_keys={"some-other-key"})
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_neg013_concurrent_duplicate_coalesces(ctx):
    auth = ctx["authorize"](consumed_approval_ids={"ap1"})
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_neg009_timeout_is_out_of_scope(ctx):
    assert ctx["authorize"]().authorized is True


# ── NEG-ACT-007 + F1: publisher trust is DERIVED from the effect kind ──
def test_neg007_deploy_untrusted_publisher_requires_approval(ctx):
    auth = ctx["authorize"](effect_kind="DEPLOY", publisher_fingerprint="pub-xyz",
                            trusted_publisher_fingerprints=set())
    assert not auth.authorized and auth.denial.code == "approval_required"
    assert auth.denial.retryable is True


def test_f1_deploy_without_publisher_fails_closed(ctx):
    # artifact strategy + NO fingerprint ⇒ cannot be silently installed (can't skip via opt-out)
    auth = ctx["authorize"](effect_kind="DEPLOY", publisher_fingerprint=None)
    assert not auth.authorized and auth.denial.code == "approval_required"


def test_f1_instantiate_without_publisher_fails_closed(ctx):
    auth = ctx["authorize"](effect_kind="INSTANTIATE", publisher_fingerprint=None)
    assert not auth.authorized and auth.denial.code == "approval_required"


def test_f1_connect_needs_no_publisher(ctx):
    assert ctx["authorize"](effect_kind="CONNECT").authorized is True


def test_f1_unknown_effect_kind_fails_closed(ctx):
    auth = ctx["authorize"](effect_kind="WAT")
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_deploy_trusted_publisher_passes(ctx):
    auth = ctx["authorize"](effect_kind="DEPLOY", publisher_fingerprint="pub-xyz",
                            trusted_publisher_fingerprints={"pub-xyz"})
    assert auth.authorized is True


# ── fail-closed on incomplete inputs (HIGH-2) ──
@pytest.mark.parametrize("missing", [
    {"trusted_approver_keys": None},
    {"consumed_approval_ids": None},
    {"readiness_eligible": None},
    {"expected_audience": None},
    {"actor_key_id": ""},
])
def test_failclosed_on_missing_required_input(ctx, missing):
    auth = ctx["authorize"](**missing)
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


# ── F2: malformed (non-None) inputs DENY, never raise ──
def test_f2_malformed_iterable_denies_not_raises(ctx):
    auth = ctx["authorize"](trusted_approver_keys=123)  # set(123) would raise
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_f2_malformed_max_attempts_denies_not_raises(ctx):
    auth = ctx["authorize"](grant=ctx["grant"](max_attempts="abc"))  # int("abc") would raise
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


# ── F3: readiness must be exactly True (truthy non-bool rejected) ──
def test_f3_non_bool_readiness_denied(ctx):
    auth = ctx["authorize"](readiness_eligible="false")  # truthy string must NOT authorize
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_exhausted_single_use_budget_denied(ctx):
    auth = ctx["authorize"](grant=ctx["grant"](max_attempts=0))
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


# ── final RE-review: a truthy NON-STRING actor_key_id must fail closed, not bypass self-approval ──
def test_nonstring_actor_key_fails_closed(ctx):
    auth = ctx["authorize"](actor_key_id=object())
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED


def test_self_approval_via_bytes_key_denied(ctx):
    # the approver self-approving, their key_id reaching the gate as BYTES, must NOT slip past the
    # str-vs-str self-approval compare — it must DENY (NEG-ACT-011 / ADR-002 out-of-band approver).
    auth = ctx["authorize"](actor_key_id=ctx["approver"].key_id.encode())
    assert not auth.authorized and auth.denial.code == ACTIVATION_NOT_AUTHORIZED
