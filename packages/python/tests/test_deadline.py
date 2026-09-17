"""Absolute-deadline gate + propagation (proposal 0052, CAP-005/006)."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from chp_core import (CapabilityDescriptor, InvocationEnvelope, LocalCapabilityHost,
                      SQLiteEvidenceStore)
from chp_core.temporal import deadline_exceeded


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _past():
    return _iso(datetime.now(timezone.utc) - timedelta(minutes=5))


def _future():
    return _iso(datetime.now(timezone.utc) + timedelta(minutes=5))


@pytest.fixture()
def host():
    d = tempfile.mkdtemp()
    h = LocalCapabilityHost("dl-host", store=SQLiteEvidenceStore(d + "/h.sqlite"))
    h.register(CapabilityDescriptor(id="demo.echo", version="1.0.0", description="e"),
               lambda ctx, p: {"saw_deadline": ctx.envelope.deadline})

    async def parent(ctx, p):
        child = await ctx.ainvoke("demo.echo", {})
        return {"child_outcome": child.outcome,
                "child_saw": child.data.get("saw_deadline") if child.data else None,
                "child_denial": child.denial.code if child.denial else None}

    h.register(CapabilityDescriptor(id="demo.parent", version="1.0.0", description="p"), parent)
    return h


def _inv(host, **kw):
    return asyncio.run(host.ainvoke_envelope(InvocationEnvelope(capability_id=kw.pop("cap"), **kw)))


def test_deadline_omit_when_none_is_byte_identical():
    # An envelope with no deadline serializes without the key (byte-identical pre-0052).
    assert "deadline" not in InvocationEnvelope(capability_id="demo.echo").to_dict()
    # A set deadline round-trips.
    e = InvocationEnvelope.from_mapping({"capability_id": "demo.echo", "deadline": _future()})
    assert e.to_dict()["deadline"] == e.deadline


def test_deadline_malformed_rejected_at_boundary():
    with pytest.raises(ValueError):
        InvocationEnvelope.from_mapping({"capability_id": "demo.echo", "deadline": "not-a-time"})


def test_past_deadline_denied_before_execution(host):
    r = _inv(host, cap="demo.echo", deadline=_past())
    assert r.outcome == "denied" and r.denial.code == "deadline_exceeded"
    assert r.denial.retryable is False
    # The handler never ran: no result data.
    assert not r.data


def test_future_deadline_runs(host):
    r = _inv(host, cap="demo.echo", deadline=_future())
    assert r.outcome == "success"


def test_absent_deadline_unchanged(host):
    assert _inv(host, cap="demo.echo").outcome == "success"


def test_deadline_propagates_to_sub_invocation_unchanged(host):
    # CAP-005: a governed sub-invocation inherits the caller's ABSOLUTE deadline verbatim.
    dl = _future()
    r = _inv(host, cap="demo.parent", deadline=dl)
    assert r.outcome == "success"
    assert r.data["child_outcome"] == "success"
    assert r.data["child_saw"] == dl          # the child saw the parent's exact deadline
    assert r.data["child_denial"] is None


def test_deadline_exceeded_helper_fails_closed():
    # None never expires; a clear future/past compares correctly; unparseable or missing
    # 'now' with a live deadline fails CLOSED (treated as exceeded, TIME-006).
    assert deadline_exceeded(None, _future()) is False
    assert deadline_exceeded(_past(), _future()) is True
    assert deadline_exceeded(_future(), _past()) is False
    assert deadline_exceeded("garbage", _future()) is True      # unparseable deadline -> closed
    assert deadline_exceeded(_future(), None) is True           # no 'now' -> closed
    # skew tolerance: a deadline 1s in the past is NOT exceeded with a 5s skew allowance.
    just_past = _iso(datetime.now(timezone.utc) - timedelta(seconds=1))
    assert deadline_exceeded(just_past, _iso(datetime.now(timezone.utc)), skew_seconds=5) is False
