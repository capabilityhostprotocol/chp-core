"""Smoke tests for the CHP→MCP server surface (previously untested, 497 LOC).

Covers the pure mapping helpers — capability→Tool, result formatting, status
filtering — without standing up the async MCP transport.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from chp_host.mcp_server import (  # noqa: E402
    _build_name_index,
    _cap_id_to_tool_name,
    _filter_caps_by_status,
    _format_result,
    _make_tool,
)


def test_cap_id_to_tool_name_and_index_roundtrip():
    assert _cap_id_to_tool_name("chp.adapters.git.status") == "chp_adapters_git_status"
    caps = [{"id": "chp.adapters.git.status"}, {"id": "chp.echo"}]
    idx = _build_name_index(caps)
    assert idx["chp_adapters_git_status"] == "chp.adapters.git.status"
    assert idx["chp_echo"] == "chp.echo"


def test_make_tool_maps_risk_and_annotations():
    low = _make_tool({"id": "chp.read", "description": "Read.", "risk": "low"})
    assert low.name == "chp_read"
    assert low.annotations.readOnlyHint is True
    assert low.annotations.destructiveHint is False

    high = _make_tool({"id": "chp.deploy", "description": "Deploy.", "risk": "high"})
    assert "[risk:high]" in high.description
    assert high.annotations.destructiveHint is True
    assert high.annotations.readOnlyHint is False
    # input schema defaulted when absent
    assert high.inputSchema.get("type") == "object"


def test_format_result_carries_outcome_and_evidence():
    text = _format_result("denied", None, {"code": "policy_blocked"}, ["evt_1"])
    assert '"outcome": "denied"' in text
    assert "policy_blocked" in text
    assert "evt_1" in text


def test_filter_caps_by_status():
    caps = [{"id": "a", "status": "certified"}, {"id": "b", "status": "draft"}]
    certified = _filter_caps_by_status(caps, "certified")
    assert [c["id"] for c in certified] == ["a"]
    # a low bar keeps everything
    assert len(_filter_caps_by_status(caps, "draft")) == 2
