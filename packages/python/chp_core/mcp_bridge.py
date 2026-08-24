"""Generic CHP host → MCP bridge — expose any CHP host's capabilities as MCP tools.

MCP is a CHP TRANSPORT (spec §transport-independence): the same capability is the same capability whether
reached over CHP-native HTTP, MCP, or A2A (CHP-CAP identity stable across interfaces). This bridge projects a
host's registered capabilities as MCP tools so ANY MCP agent (Claude, Cursor, …) discovers and invokes them
natively — one generic bridge reused by every product, NOT a per-product MCP server (that siloes the bridge).

The ``mcp`` package is an OPTIONAL dependency (``pip install chp-core[mcp]``) — chp_core stays dependency-free,
so importing this module is fine without it; only ``serve_mcp`` needs it. The tool SCHEMA reuses
``agent_interface.capability_to_anthropic_tool`` (the same descriptor projection the Anthropic/OpenAI bridges
use), and a call is projected HONESTLY from the InvocationResult — outcome + data or denial, never a fabricated
success (a denied capability stays denied over MCP exactly as over HTTP).
"""

from __future__ import annotations

from typing import Any

from .agent_interface import capability_to_anthropic_tool


def _descriptors(host: Any) -> list[Any]:
    """The host's capability descriptors, from a public accessor if present, else a LocalCapabilityHost's
    registry. Kept small + duck-typed so the bridge works over any host shape."""
    for attr in ("list_capabilities", "descriptors"):
        val = getattr(host, attr, None)
        if callable(val):
            return list(val())
        if val is not None:
            return list(val)
    caps = getattr(host, "_capabilities", None)  # LocalCapabilityHost registry
    if caps is not None:
        return [entry.descriptor for entry in caps.values()]
    raise TypeError("host does not expose capabilities (no list_capabilities/descriptors/_capabilities)")


def capabilities_to_mcp_tools(descriptors: list[Any]) -> tuple[list[dict], dict[str, str]]:
    """Project CHP descriptors → (MCP tool dicts, name→capability-id map). Pure — no ``mcp`` needed, so it is
    fully unit-testable. Reuses ``capability_to_anthropic_tool``; the only shape difference from the Anthropic
    tool format is the schema key (``input_schema`` → MCP's ``inputSchema``). The tool name is the capability id
    with dots→underscores (MCP tool-name convention); the returned map recovers the real id for dispatch."""
    tools: list[dict] = []
    name_to_id: dict[str, str] = {}
    for d in descriptors:
        t = capability_to_anthropic_tool(d)
        tools.append({"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]})
        name_to_id[t["name"]] = d.id
    return tools, name_to_id


def _project_result(res: Any) -> dict:
    """Project an InvocationResult HONESTLY for the MCP caller — the observed outcome + data or denial, never a
    fabricated success. A denied capability reads as denied over MCP exactly as over HTTP (CHP-VER honesty)."""
    return {
        "outcome": getattr(res, "outcome", None),
        "data": getattr(res, "data", None),
        "denial": getattr(res, "denial", None),
        "evidence_ids": getattr(res, "evidence_ids", None),
    }


def serve_mcp(host: Any, *, name: str = "chp", descriptors: list[Any] | None = None) -> Any:
    """Build an MCP ``Server`` exposing ``host``'s capabilities as tools (needs ``chp-core[mcp]``). Each tool
    invokes ``host.ainvoke(capability_id, arguments)`` and returns the honestly-projected result. Returns the
    server; run it yourself (``mcp.server.stdio``), or call :func:`run_stdio`.

    ``host`` is anything exposing ``ainvoke(capability_id, payload)`` + its descriptors (a ``LocalCapabilityHost``,
    or a ``RemoteCapabilityHost`` pointing at a served host — the market on :8857, a mesh node, …)."""
    try:
        from mcp.server import Server
        from mcp.types import TextContent, Tool
    except ImportError as exc:  # optional dep — chp_core is dependency-free
        raise ImportError("the CHP→MCP bridge needs the optional `mcp` dependency: pip install chp-core[mcp]") from exc
    import json

    descs = descriptors if descriptors is not None else _descriptors(host)
    tool_dicts, name_to_id = capabilities_to_mcp_tools(descs)
    server = Server(name)

    @server.list_tools()
    async def _list_tools() -> list[Any]:
        return [Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]) for t in tool_dicts]

    @server.call_tool()
    async def _call_tool(tool_name: str, arguments: dict | None) -> list[Any]:
        cap_id = name_to_id.get(tool_name)
        if cap_id is None:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool {tool_name!r}"}))]
        res = await host.ainvoke(cap_id, arguments or {})
        return [TextContent(type="text", text=json.dumps(_project_result(res), default=str))]

    return server


async def run_stdio(host: Any, *, name: str = "chp") -> None:
    """Serve ``host`` over MCP on stdio — register this with an MCP client to give an agent the host's caps."""
    from mcp.server.stdio import stdio_server

    server = serve_mcp(host, name=name)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
