"""Small MCP-style bridge prototype for CHP v0.1.

This file intentionally avoids a hard dependency on the MCP SDK. It demonstrates
the concept that an MCP-style tool can be wrapped as a CHP capability, and that
a CHP capability can be exposed through an MCP-compatible tool surface.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore  # noqa: E402

ToolHandler = Callable[[dict[str, Any]], Any | Awaitable[Any]]


@dataclass(slots=True)
class McpLikeTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


def tool_name_to_capability_id(name: str, namespace: str = "mcp") -> str:
    return f"{namespace}.{name.replace('-', '_').replace('.', '_')}"


def wrap_mcp_tool_as_capability(
    host: LocalCapabilityHost,
    tool: McpLikeTool,
    *,
    namespace: str = "mcp",
) -> CapabilityDescriptor:
    capability_id = tool_name_to_capability_id(tool.name, namespace)

    async def handler(ctx, payload):
        ctx.emit(
            "mcp_tool_call_observed",
            {
                "tool_name": tool.name,
                "capability_id": capability_id,
            },
        )
        result = tool.handler(payload)
        return await result if asyncio.iscoroutine(result) else result

    descriptor = CapabilityDescriptor(
        id=capability_id,
        version="0.1.0",
        description=f"MCP-style tool wrapped as CHP capability: {tool.description}",
        input_schema=tool.input_schema,
        tags=["mcp", "bridge"],
        emits=["execution_started", "mcp_tool_call_observed", "execution_completed", "execution_failed"],
    )
    host.register(descriptor, handler)
    return descriptor


def expose_chp_capability_as_mcp_tool(
    host: LocalCapabilityHost,
    capability_id: str,
    *,
    tool_name: str | None = None,
) -> McpLikeTool:
    descriptor = next(
        cap
        for cap in host.discover()["capabilities"]
        if cap["id"] == capability_id or cap["capability_uri"] == capability_id
    )

    async def handler(params: dict[str, Any]) -> dict[str, Any]:
        result = await host.ainvoke(
            descriptor["id"],
            params,
            correlation={"correlation_id": params.get("correlation_id", "mcp-bridge-demo")},
            subject={"id": "mcp-client", "type": "agent"},
        )
        return result.to_dict()

    return McpLikeTool(
        name=tool_name or descriptor["id"].replace(".", "_"),
        description=descriptor["description"],
        input_schema=descriptor.get("input_schema") or {},
        handler=handler,
    )


async def demo() -> None:
    host = LocalCapabilityHost("mcp-bridge-demo", store=SQLiteEvidenceStore(":memory:"))

    async def search_docs(params: dict[str, Any]) -> dict[str, Any]:
        query = params["query"]
        return {"matches": [{"title": "CHP v0.1", "snippet": f"Result for {query}"}]}

    mcp_tool = McpLikeTool(
        name="search-docs",
        description="Search local documentation.",
        input_schema={
            "type": "object",
            "required": ["query"],
            "properties": {"query": {"type": "string"}},
        },
        handler=search_docs,
    )
    wrapped = wrap_mcp_tool_as_capability(host, mcp_tool)

    wrapped_result = await host.ainvoke(
        wrapped.id,
        {"query": "evidence"},
        correlation={"correlation_id": "mcp-bridge-demo"},
        subject={"id": "demo-agent", "type": "agent"},
    )

    exposed_tool = expose_chp_capability_as_mcp_tool(host, wrapped.id)
    exposed_result = await exposed_tool.handler({"query": "correlation", "correlation_id": "mcp-bridge-demo-2"})

    print(json.dumps({
        "wrapped_capability": wrapped.to_dict(),
        "wrapped_result": wrapped_result.to_dict(),
        "exposed_tool": {
            "name": exposed_tool.name,
            "description": exposed_tool.description,
            "input_schema": exposed_tool.input_schema,
        },
        "exposed_result": exposed_result,
        "replay": host.replay("mcp-bridge-demo"),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(demo())
