"""M1.3 activation-effect gate wired into the live pipeline (ADR-002, HOST-002/003/004).

Exercises authorize_activation_effect THROUGH LocalCapabilityHost._prepare via an envelope's
activation_ref: the host independently authorizes, atomically consumes the grant, and the step is a
strict no-op when activation_ref is absent.
"""
from __future__ import annotations

import asyncio
import tempfile

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.host import _stringify_floats
from chp_core.signing import build_approval_grant, generate_keypair
from chp_core.store import _payload_commitment
from chp_core.types import InvocationEnvelope

AUD = "acme:owned-host-1"
FUTURE = "2099-01-01T00:00:00Z"
PLAN = "sha256:" + "c" * 64


def _run(c):
    return asyncio.run(c)


def _commit(p):
    return _payload_commitment(_stringify_floats(p))


def _host():
    calls = {"n": 0}
    host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def work(_c, p):
        calls["n"] += 1
        return {"ok": True}

    host.register(CapabilityDescriptor(id="deploy.cap", version="1.0.0", description="."), work)
    return host, calls, generate_keypair(tempfile.mkdtemp())


def _grant(approver, inv, payload, approval_id="ap1", **over):
    kw = dict(invocation_id=inv, payload_commitment=_commit(payload), approval_id=approval_id,
              valid_until=FUTURE, action_digest=PLAN, audience=AUD, max_attempts=1)
    kw.update(over)
    return build_approval_grant(approver, **kw)


def _act(**over):
    a = {"plan_digest": PLAN, "effect_kind": "CONNECT", "readiness_eligible": True}
    a.update(over)
    return a


def _configure(mp, approver):
    mp.setenv("CHP_HOST_APPROVER_KEYS", approver.key_id)
    mp.setenv("CHP_HOST_ACTIVATION_AUDIENCE", AUD)


def _env(approver, inv="inv-a", key="agent-x-key", act=None, grant_over=None):
    payload = {"x": 1}
    return InvocationEnvelope(
        capability_id="deploy.cap", invocation_id=inv, payload=payload,
        approval_ref=_grant(approver, inv, payload, **(grant_over or {})),
        activation_ref=act if act is not None else _act(),
        subject={"id": "agent-x", "key_id": key, "verified": True})


def test_no_activation_ref_is_ordinary_invocation(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    r = _run(host.ainvoke_envelope(InvocationEnvelope(capability_id="deploy.cap", payload={"x": 1})))
    assert r.outcome == "success" and calls["n"] == 1  # activation gate skipped entirely


def test_configured_host_authorizes_and_executes(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    r = _run(host.ainvoke_envelope(_env(approver)))
    assert r.outcome == "success" and calls["n"] == 1


def test_replay_same_grant_denied_after_atomic_consume(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    assert _run(host.ainvoke_envelope(_env(approver, inv="inv-a"))).outcome == "success"
    # same approval_id, NEW invocation_id (bypass idempotent replay) → already consumed → deny
    r2 = _run(host.ainvoke_envelope(_env(approver, inv="inv-b")))
    assert r2.outcome == "denied" and r2.denial.code == "activation_not_authorized"
    assert calls["n"] == 1  # effect ran exactly once


def test_unconfigured_host_fails_closed(monkeypatch):
    host, calls, approver = _host()
    monkeypatch.delenv("CHP_HOST_APPROVER_KEYS", raising=False)
    monkeypatch.delenv("CHP_HOST_ACTIVATION_AUDIENCE", raising=False)
    r = _run(host.ainvoke_envelope(_env(approver)))
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0


def test_self_approval_denied_in_pipeline(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    r = _run(host.ainvoke_envelope(_env(approver, key=approver.key_id)))  # actor key == approver key
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0


def test_untrusted_approver_denied_in_pipeline(monkeypatch):
    host, calls, approver = _host()
    monkeypatch.setenv("CHP_HOST_APPROVER_KEYS", "some-other-key")  # approver not trusted
    monkeypatch.setenv("CHP_HOST_ACTIVATION_AUDIENCE", AUD)
    r = _run(host.ainvoke_envelope(_env(approver)))
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0


def test_deploy_requires_trusted_publisher_in_pipeline(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    r = _run(host.ainvoke_envelope(_env(
        approver, act=_act(effect_kind="DEPLOY", publisher_fingerprint="pub-x"))))
    assert r.outcome == "denied" and r.denial.code == "approval_required"
    assert calls["n"] == 0


def test_wrong_plan_digest_denied_in_pipeline(monkeypatch):
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    r = _run(host.ainvoke_envelope(_env(approver, act=_act(plan_digest="sha256:" + "d" * 64))))
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0


def test_concurrent_activation_double_spend_prevented(monkeypatch):
    # review F-1: N concurrent invocations (distinct invocation_ids to bypass idempotent replay) of
    # the SAME approval_id grant, through ONE shared host on the DEFAULT (:memory:) store, must
    # execute the effect EXACTLY ONCE. (Pre-fix: 5/5 double-spent.)
    from concurrent.futures import ThreadPoolExecutor
    host, calls, approver = _host()
    _configure(monkeypatch, approver)

    def attempt(i):
        payload = {"x": 1}
        g = _grant(approver, f"inv-{i}", payload, approval_id="hot")
        env = InvocationEnvelope(
            capability_id="deploy.cap", invocation_id=f"inv-{i}", payload=payload,
            approval_ref=g, activation_ref=_act(),
            subject={"id": "agent-x", "key_id": "agent-x-key", "verified": True})
        return asyncio.run(host.ainvoke_envelope(env)).outcome

    with ThreadPoolExecutor(max_workers=12) as ex:
        outcomes = list(ex.map(attempt, range(12)))
    assert sum(1 for o in outcomes if o == "success") == 1, outcomes
    assert calls["n"] == 1  # effect executed exactly once


def test_activation_path_exception_fails_closed(monkeypatch):
    # review F-2: if the activation authorization path raises, the pipeline must DENY (governed +
    # evidenced), never let the exception escape and drop the effect's governance.
    host, calls, approver = _host()
    _configure(monkeypatch, approver)

    def boom(_env):
        raise RuntimeError("induced failure in the activation path")

    monkeypatch.setattr(host, "_authorize_activation", boom)
    r = _run(host.ainvoke_envelope(_env(approver)))
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0  # no effect ran


def test_unverified_subject_key_id_not_trusted(monkeypatch):
    # review F-3: an UNVERIFIED subject key_id (or caller-asserted actor) must NOT feed the
    # self-approval check. Here the approver is the actor but only via an UNVERIFIED subject →
    # actor_key_id resolves to "" → gate fails closed (deny), not an inert pass.
    host, calls, approver = _host()
    _configure(monkeypatch, approver)
    env = InvocationEnvelope(
        capability_id="deploy.cap", invocation_id="inv-a", payload={"x": 1},
        approval_ref=_grant(approver, "inv-a", {"x": 1}), activation_ref=_act(),
        subject={"id": "x", "key_id": "agent-x-key", "verified": False},  # NOT verified
        actor={"id": "x", "key_id": "agent-x-key"})                       # caller-asserted (ignored)
    r = _run(host.ainvoke_envelope(env))
    assert r.outcome == "denied" and r.denial.code == "activation_not_authorized"
    assert calls["n"] == 0
