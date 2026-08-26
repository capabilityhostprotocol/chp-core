"""Capability withdrawal surface (GAP-SRV-004): set_enabled / unregister.

Withdrawal changes FUTURE admission only — recorded results and the evidence
chain are never rewritten (retirement never mutates execution truth).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from chp_core import CapabilityDescriptor, InvocationEnvelope, LocalCapabilityHost, SQLiteEvidenceStore


@pytest.fixture()
def host():
    h = LocalCapabilityHost("wd-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_ctx, payload):
        return {"echo": payload.get("v")}

    h.register(CapabilityDescriptor(id="demo.echo", version="1.0.0", description="e"), echo)
    return h


async def _invoke(host, inv_id="inv-1"):
    return await host.ainvoke_envelope(InvocationEnvelope(
        capability_id="demo.echo", payload={"v": "x"}, invocation_id=inv_id))


async def test_set_enabled_false_denies_capability_disabled(host):
    assert (await _invoke(host)).outcome == "success"
    assert host.set_enabled("demo.echo", False) == 1
    r = await _invoke(host, "inv-2")
    assert r.outcome == "skipped"  # Gate 3 skip semantics
    assert host.set_enabled("demo.echo", True) == 1
    assert (await _invoke(host, "inv-3")).outcome == "success"


async def test_unregister_denies_capability_not_found(host):
    assert host.unregister("demo.echo") == 1
    r = await _invoke(host)
    assert r.outcome == "denied" and r.denial.code == "capability_not_found"
    assert host.discover()["capabilities"] == []


async def test_withdrawal_never_rewrites_recorded_truth(host):
    first = await _invoke(host, "inv-keep")
    assert first.outcome == "success"
    host.unregister("demo.echo")
    # Gate 0 idempotent replay of the recorded invocation still returns the
    # recorded result — retirement affects future admission only.
    replayed = await _invoke(host, "inv-keep")
    assert replayed.outcome == "success" and replayed.data == first.data


def test_bare_id_and_full_uri_addressing(host):
    assert host.set_enabled("demo.echo:1.0.0", False) == 1  # full capability_uri
    assert host.set_enabled("no.such", False) == 0
    assert host.unregister("demo.echo") == 1                 # bare id, all versions
    assert host.unregister("demo.echo") == 0
