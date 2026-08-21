"""Authority MUST-NOT prohibition tests (proposal — post-audit; CHP-AUTH-011/014/016/018).

The invariants were implemented; these are the dedicated prohibition tests they lacked. Each proves
a NEGATIVE: a role is not authority, a valid mandate is not admission, revocation does not rewrite
history, and invoking a service is not delegation.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from chp_core import (
    CapabilityDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    signing,
)
from chp_core.policy import PolicyConfig


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mandate(key, *, delegate="steward-x", scope=("demo.echo",), hours=1):
    now = datetime.now(timezone.utc)
    return signing.build_mandate(
        "principal-a", key, delegate_id=delegate, scope=list(scope),
        valid_from=_iso(now - timedelta(minutes=1)),
        valid_until=_iso(now + timedelta(hours=hours)), created_at=_iso(now))


def _host(*, policy=None, allowed_actors=None):
    h = LocalCapabilityHost("test-host", store=SQLiteEvidenceStore(":memory:"), policy=policy)

    async def handler(_ctx, payload):
        return {"echo": payload.get("value")}

    pol = None
    if allowed_actors is not None:
        from chp_core.types import PolicyDescriptor
        pol = PolicyDescriptor(allowed_actors=list(allowed_actors))
    h.register(CapabilityDescriptor(id="demo.echo", version="1.0.0", description="Echo.", policy=pol),
               handler)
    return h


def _key():
    return signing.generate_keypair(Path(tempfile.mkdtemp()) / "pub")


# ---- CHP-AUTH-011: a role/relationship is not execution authority ----

def test_role_alone_is_not_authority():
    # A subject carrying a role but NO signed mandate gets NO mandate-authority: the recorded
    # subject is never elevated to type "mandate" — a role attribute cannot become authority.
    h = _host()
    res = asyncio.run(h.ainvoke_envelope(InvocationEnvelope(
        capability_id="demo.echo", payload={"value": "x"},
        subject={"id": "role-holder", "role": "admin", "verified": True})))
    assert res.outcome == "success"
    subj = h.replay(res.correlation.correlation_id)[0].get("subject") or {}
    assert subj.get("type") != "mandate"          # role did not confer delegated authority
    assert "mandate_id" not in subj and "root_principal" not in subj


# ---- CHP-AUTH-014: a valid mandate is not admission (later gates still apply) ----

def test_valid_mandate_still_denied_by_a_later_gate():
    # The mandate is valid AND in-scope (gate 5 passes + rebinds to steward-x), but the per-actor
    # allowlist (a LATER gate) admits only someone else → denied. Authority ≠ admission.
    h = _host(allowed_actors=["someone-else"])
    res = asyncio.run(h.ainvoke_envelope(InvocationEnvelope(
        capability_id="demo.echo", payload={"value": "x"}, mandate=_mandate(_key()))))
    assert res.outcome == "denied"
    assert res.denial is not None and res.denial.code == "policy_blocked"  # NOT mandate_invalid
    # proof gate 5 passed first: the message names the allowlist, not a mandate failure
    assert "allowed_actors" in (res.denial.message + str(res.denial.details))


# ---- CHP-AUTH-016: revocation is forward-only; it does not rewrite past evidence ----

def test_revocation_does_not_rewrite_prior_evidence():
    key = _key()
    mandate = _mandate(key)
    h = _host()
    res = asyncio.run(h.ainvoke_envelope(InvocationEnvelope(
        capability_id="demo.echo", payload={"value": "x"}, mandate=mandate)))
    assert res.outcome == "success"
    corr = res.correlation.correlation_id
    before = [(e.get("event_id"), e.get("content_hash")) for e in h.replay(corr)]

    # Revoke the mandate — it is now dead going FORWARD (verify fails)...
    rev = signing.build_mandate_revocation(mandate, key, revoked_at=_iso(datetime.now(timezone.utc)))
    assert not signing.verify_mandate(mandate, at_time=_iso(datetime.now(timezone.utc)),
                                      revocations=[rev]).valid
    # ...but the already-admitted execution's evidence is byte-unchanged (append-only history).
    after = [(e.get("event_id"), e.get("content_hash")) for e in h.replay(corr)]
    assert after == before


# ---- CHP-AUTH-018: invoking a service is not delegation ----

def test_service_call_creates_no_requester_provider_delegation():
    # A plain call to a provider's capability (no mandate) records NO delegation binding between
    # the requesting actor and the provider — invoking a service ≠ delegating authority.
    h = _host()
    res = asyncio.run(h.ainvoke_envelope(InvocationEnvelope(
        capability_id="demo.echo", payload={"value": "x"},
        actor={"id": "requester-r"})))
    assert res.outcome == "success"
    subj = h.replay(res.correlation.correlation_id)[0].get("subject") or {}
    # no mandate/delegation relationship was manufactured from the service call
    assert subj.get("type") != "mandate"
    assert not {"mandate_id", "root_principal", "delegate_id"} & set(subj)
