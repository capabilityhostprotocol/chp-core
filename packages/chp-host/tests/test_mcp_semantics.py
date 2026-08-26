"""MCP semantic-loss conformance (CHP-SRV-MCP-002..006/008).

Drives the export bridge's pure mapping surface: canonical identity survives
tool-name mapping, governance semantics are not stripped from tool metadata,
denials keep their inspectable cause, and status gating is the non-exportable
mechanism.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

from chp_core.types import DenialReason  # noqa: E402
from chp_host.mcp_server import (  # noqa: E402
    _build_name_index,
    _cap_id_to_tool_name,
    _filter_caps_by_status,
    _format_result,
    _make_tool,
)


def test_mcp_005_canonical_identity_survives_mapping():
    # The mangling is not naively reversible (ids may contain underscores);
    # the startup name index is the lossless map back to canonical identity.
    caps = [{"id": "chp.adapters.git.status"}, {"id": "chp.adapters.knowledge_graph.add_node"}]
    index = _build_name_index(caps)
    assert index[_cap_id_to_tool_name("chp.adapters.git.status")] == "chp.adapters.git.status"
    assert index["chp_adapters_knowledge_graph_add_node"] == "chp.adapters.knowledge_graph.add_node"


def test_mcp_003_governance_semantics_not_stripped():
    tool = _make_tool({
        "id": "danger.op", "description": "Does things.", "risk": "high",
        "side_effects": ["writes"], "idempotency": "required",
        "safety_hint": {"destructive": True},
        "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}})
    assert tool.description.startswith("[risk:high]")  # risk surfaces, never dropped
    assert tool.annotations.destructiveHint is True
    assert tool.annotations.readOnlyHint is False       # side effects visible
    assert tool.annotations.idempotentHint is True      # effect-safety semantics carried
    tool_ro = _make_tool({"id": "read.op", "description": "Reads.", "risk": "low"})
    assert tool_ro.annotations.readOnlyHint is True


def test_mcp_006_denial_cause_is_inspectable():
    text = _format_result("denied", None, None, ["evt_1"], denial=DenialReason(
        code="policy_blocked", message="outside mandate scope", retryable=False))
    payload = json.loads(text)
    assert payload["outcome"] == "denied"
    assert payload["denial"]["code"] == "policy_blocked"
    assert payload["denial"]["message"] == "outside mandate scope"
    assert payload["_evidence_ids"] == ["evt_1"]


def test_mcp_006_success_and_error_shapes_stay_inspectable():
    ok = json.loads(_format_result("success", {"a": 1}, None, []))
    assert ok == {"outcome": "success", "data": {"a": 1}}
    err = json.loads(_format_result("failure", None, "boom", ["evt_2"]))
    assert err["error"] == "boom" and err["_evidence_ids"] == ["evt_2"]


def test_mcp_004_status_gating_is_the_non_exportable_mechanism():
    caps = [{"id": "a", "status": "draft"}, {"id": "b", "status": "experimental"},
            {"id": "c", "status": "certified"}, {"id": "d", "status": "deprecated"},
            {"id": "e"}]  # no status -> draft
    # Raising min_status is the non-exportable mechanism: immature capabilities
    # are simply not flattened into MCP tools.
    assert [c["id"] for c in _filter_caps_by_status(caps, "experimental")] == ["b", "c"]
    assert [c["id"] for c in _filter_caps_by_status(caps, "certified")] == ["c"]
    # Even at the default floor, deprecated capabilities are never exported.
    assert [c["id"] for c in _filter_caps_by_status(caps, "draft")] == ["a", "b", "c", "e"]


def test_mcp_002_043_import_preserves_raw_provenance_without_elevation():
    pytest.importorskip("chp_server")
    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
    from chp_server import IntroductionCoordinator
    from chp_host.server_port import McpImportSource

    src = McpImportSource("mcp://tools.example", [
        {"name": "web_search", "description": "Searches.", "inputSchema": {"type": "object"}}])
    host = LocalCapabilityHost("mcp-import-host", store=SQLiteEvidenceStore(":memory:"))
    coord = IntroductionCoordinator(host)
    out = coord.activate(src.snapshot())
    cid = "mcp-tool:mcp://tools.example:web_search"
    assert out["activated"] == [cid]
    fact = coord.active[cid]
    # Raw-tool provenance preserved; the fact is a semantic_mapping CLAIM...
    assert fact["fact_class"] == "semantic_mapping"
    assert fact["payload"]["raw"] is True and fact["payload"]["origin"] == "mcp://tools.example"
    # ...and NOTHING was elevated into a governed capability (no live-state integration).
    assert host.discover()["capabilities"] == []
    with pytest.raises(ValueError):
        McpImportSource("", [])