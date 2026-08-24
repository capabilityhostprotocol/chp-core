"""Generic CHP→MCP bridge — a host's capabilities project to MCP tools (the pure mapping; no `mcp` dep needed).

MCP is a CHP transport: the same capability id, reachable natively by any MCP agent, with the tool schema reused
from the Anthropic/OpenAI projection and a denial projected honestly (verified in the integration path)."""

from chp_core import (
    CapabilityDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    capabilities_to_mcp_tools,
)
from chp_core.mcp_bridge import _descriptors


def _host():
    h = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    h.register(CapabilityDescriptor(id="chp.market.resolve", version="1.0.0",
                                    description="Resolve a requirement",
                                    input_schema={"type": "object", "properties": {"capability_id": {"type": "string"}}}),
               lambda _c, _p: {"ok": True})
    h.register(CapabilityDescriptor(id="mesh.inference.chat", version="1.0.0", description="Sovereign inference"),
               lambda _c, _p: {"ok": True})
    return h


def test_capabilities_project_to_mcp_tools_with_id_recovery():
    tools, name_to_id = capabilities_to_mcp_tools(_descriptors(_host()))
    by_name = {t["name"]: t for t in tools}
    # dotted capability id → underscored MCP tool name; the map recovers the real id for dispatch
    assert "chp_market_resolve" in by_name and name_to_id["chp_market_resolve"] == "chp.market.resolve"
    assert "mesh_inference_chat" in by_name and name_to_id["mesh_inference_chat"] == "mesh.inference.chat"
    # the input schema carries through under MCP's key; a schema-less cap gets an empty-object schema
    assert by_name["chp_market_resolve"]["inputSchema"]["properties"] == {"capability_id": {"type": "string"}}
    assert by_name["mesh_inference_chat"]["inputSchema"] == {"type": "object", "properties": {}}
    assert by_name["chp_market_resolve"]["description"] == "Resolve a requirement"


def test_descriptors_enumerates_a_local_host():
    ids = {d.id for d in _descriptors(_host())}
    assert ids == {"chp.market.resolve", "mesh.inference.chat"}


def test_module_imports_without_the_optional_mcp_dep():
    # importing the bridge + the pure mapping must not require `mcp` (chp_core stays dependency-free);
    # only serve_mcp() needs it, and then raises a clear install hint.
    import importlib

    import chp_core.mcp_bridge as mb
    importlib.reload(mb)
    assert callable(mb.capabilities_to_mcp_tools) and callable(mb.serve_mcp)
