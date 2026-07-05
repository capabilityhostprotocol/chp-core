"""Tests for W3C PROV-JSON export — signed, governed provenance."""

from __future__ import annotations

import asyncio

from chp_core import (
    CapabilityDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core.prov import replay_to_prov
from chp_core.safety import RuleBasedSafetyEvaluator
from chp_core.types import GuardrailDefinition


def _host(tmp_path):
    ev = RuleBasedSafetyEvaluator(guardrails=[GuardrailDefinition(
        id="g", capability_id_pattern="x.unsafe", max_risk_level="critical",
        requires_human_for=["x.unsafe"])])
    return LocalCapabilityHost("h1", store=SQLiteEvidenceStore(str(tmp_path / "e.sqlite")),
                               safety_evaluator=ev)


def test_prov_maps_activity_agent_entity(tmp_path):
    host = _host(tmp_path)

    async def _h(_c, _p):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="x.act", version="1.0.0", description=""), _h)
    asyncio.run(host.ainvoke("x.act", {}, correlation={"correlation_id": "c"},
                             subject={"id": "agent-a", "type": "api_key", "verified": True}))

    doc = replay_to_prov(host.store.export_correlation("c"))
    assert doc["prefix"]["chp"].startswith("https://chp.dev/prov")
    # one Activity (the invocation), the subject Agent + host SoftwareAgent, one Entity.
    (act_id, act), = doc["activity"].items()
    assert act["chp:capability_id"] == "x.act"
    assert act["chp:outcome"] == "success"
    assert "chp:agent:agent-a" in doc["agent"]
    assert doc["agent"]["chp:agent:agent-a"]["chp:verified"] is True
    assert any(a.get("prov:type") == "prov:SoftwareAgent" for a in doc["agent"].values())
    # Entity carries the content_hash tamper anchor.
    (ent_id, ent), = doc["entity"].items()
    assert ent["prov:type"] == "chp:EvidenceRecord"
    assert ent["chp:content_hash"] and ent["chp:hash_chained"] is True
    # wasAssociatedWith links the activity to both agents; wasGeneratedBy the entity.
    assert any(w["prov:activity"] == act_id for w in doc["wasAssociatedWith"].values())
    assert any(g["prov:entity"] == ent_id for g in doc["wasGeneratedBy"].values())


def test_prov_carries_governance_and_denial(tmp_path):
    host = _host(tmp_path)

    async def _h(_c, _p):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="x.unsafe", version="1.0.0", description=""), _h)
    asyncio.run(host.ainvoke("x.unsafe", {}, correlation={"correlation_id": "c"}))

    doc = replay_to_prov(host.store.export_correlation("c"))
    (_, act), = doc["activity"].items()
    # The refusal PROV has no vocabulary for — exported as chp: annotations.
    assert act["chp:denied"] is True
    assert act["chp:denial_code"] == "safety_blocked"
    assert act["chp:safety_assessed"] is True
    assert act["chp:safety_blocked"] is True


def test_prov_causal_edge_is_was_informed_by(tmp_path):
    host = _host(tmp_path)

    async def _child(_c, _p):
        return {"ok": True}

    async def _parent(ctx, _p):
        await ctx.ainvoke("x.child", {})  # auto-propagates correlation + causation
        return {"done": True}

    host.register(CapabilityDescriptor(id="x.child", version="1.0.0", description=""), _child)
    host.register(CapabilityDescriptor(id="x.parent", version="1.0.0", description=""), _parent)
    asyncio.run(host.ainvoke("x.parent", {}, correlation={"correlation_id": "c"}))

    doc = replay_to_prov(host.store.export_correlation("c"))
    assert len(doc["activity"]) == 2, "parent + child activities"
    assert "wasInformedBy" in doc, "causal edge must map to wasInformedBy"
    (edge,) = doc["wasInformedBy"].values()
    # child (informed) was informed by parent (informant)
    assert edge["prov:informed"] != edge["prov:informant"]
    assert edge["prov:informant"] in doc["activity"]
