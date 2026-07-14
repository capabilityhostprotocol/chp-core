"""First-class actor identity (proposal 0034). The invocation subject stays the
host's verified accountability record; an OPTIONAL, additive `actor` object enriches
it and drives the per-actor allowlist (descriptor.policy.allowed_actors). The
load-bearing property: an envelope with no actor is byte-identical to pre-0034."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import Actor, CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.types import CorrelationContext, InvocationEnvelope, PolicyDescriptor


def _canon(o: object) -> str:
    return hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()


def test_actor_omit_when_absent_is_byte_identical() -> None:
    """The backward-compat guarantee: on ONE envelope (fixed correlation to avoid
    random-default confounds), an absent actor contributes zero bytes — setting
    then clearing `actor` returns the exact pre-0034 canonical bytes."""
    corr = CorrelationContext(correlation_id="fixed")
    e = InvocationEnvelope(capability_id="c.cap", invocation_id="inv1",
                           requested_at="2026-01-01T00:00:00Z", correlation=corr)
    d_none = e.to_dict()
    assert "actor" not in d_none
    e.actor = {"id": "x", "type": "agent"}
    assert "actor" in e.to_dict()  # present when set
    e.actor = None
    assert _canon(e.to_dict()) == _canon(d_none)  # cleared → byte-identical to pre-0034


def test_actor_normalizes_and_omits_empty_fields() -> None:
    a = Actor.from_mapping({"id": "alice", "type": "human", "owner": "",
                            "organization": None, "authority_refs": []})
    assert a.to_dict() == {"id": "alice", "type": "human"}
    # A minimal actor keeps just id + defaulted type.
    assert Actor.from_mapping({"id": "agent-7"}).to_dict() == {"id": "agent-7", "type": "agent"}


def test_actor_validation_rejects_bad_shapes() -> None:
    for bad in [{"id": ""}, {"id": 123}, {"id": "x", "authority_refs": "nope"}, "not-a-dict", 42]:
        try:
            Actor.from_mapping(bad)  # type: ignore[arg-type]
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass


def test_envelope_actor_round_trips() -> None:
    e = InvocationEnvelope.from_mapping({
        "capability_id": "c.cap", "invocation_id": "inv1",
        "requested_at": "2026-01-01T00:00:00Z",
        "actor": {"id": "alice", "type": "human", "organization": "acme"},
    })
    assert e.to_dict()["actor"] == {"id": "alice", "type": "human", "organization": "acme"}


def _run(coro):
    return asyncio.run(coro)


def test_allowed_actors_gate_allows_listed_denies_others() -> None:
    host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def work(_c, _p):
        return {"ok": 1}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description=".",
                                       policy=PolicyDescriptor(allowed_actors=["alice"])), work)

    async def go():
        listed = await host.ainvoke("w.cap", {}, actor={"id": "alice", "type": "human"})
        unlisted = await host.ainvoke("w.cap", {}, actor={"id": "mallory", "type": "agent"})
        no_actor = await host.ainvoke("w.cap", {})  # subject 'local' not in list
        return listed, unlisted, no_actor

    listed, unlisted, no_actor = _run(go())
    assert listed.outcome == "success"
    assert unlisted.outcome == "denied" and unlisted.denial.code == "policy_blocked"
    assert no_actor.outcome == "denied" and no_actor.denial.code == "policy_blocked"


def test_open_allowlist_permits_any_actor() -> None:
    host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def work(_c, _p):
        return {"ok": 1}

    # No policy / empty allowed_actors → open (today's behavior).
    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
    r = _run(host.ainvoke("w.cap", {}, actor={"id": "whoever"}))
    assert r.outcome == "success"


def test_actor_recorded_in_evidence() -> None:
    host = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def work(_c, _p):
        return {"ok": 1}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
    r = _run(host.ainvoke("w.cap", {}, correlation={"correlation_id": "corr-1"},
                          actor={"id": "alice", "type": "human"}))
    assert r.outcome == "success"
    events = host.store.by_correlation("corr-1")
    assert any((e.get("actor") or {}).get("id") == "alice" for e in events)


def test_actor_vector_matches_shared_algorithm() -> None:
    """The KAT vector's allowlist decisions match the Python gate semantics."""
    vec = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "actor.json"
    doc = json.loads(vec.read_text())

    def effective(c):
        subj = c.get("subject") or {}
        actor = c.get("actor") or {}
        return (subj.get("id") or "") if subj.get("verified") else (actor.get("id") or subj.get("id") or "")

    def allowed(c):
        al = c.get("allowed_actors") or []
        return True if not al else effective(c) in al

    for c in doc["cases"]:
        assert allowed(c) is c["allowed"], c["note"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
