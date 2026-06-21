"""MCPAdapter — wraps an MCP server's tools as CHP capabilities.

The host invokes capability handlers via ``asyncio.run`` (a fresh event loop
per ``host.invoke`` call). An MCP ``ClientSession`` is bound to the loop it was
created on, so we cannot reuse one session across invocations from the host's
loops. ``_ThreadedMCPSession`` therefore owns a dedicated background thread with
its own persistent event loop; the MCP session lives there for the adapter's
lifetime, and async handlers bridge to it via ``asyncio.wrap_future`` without
blocking the host's loop.

The session is abstracted behind ``_MCPSession`` so tests can inject a fake
without spawning a subprocess or thread.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from chp_core import BaseAdapter, CapabilityDescriptor, HostedCapability

MAX_ERROR_LEN = 500

# Domain events only — the host owns execution_started/completed/failed.
_EMITS = [
    "mcp_tool_called",
    "mcp_tool_result",
    "mcp_error",
]


@dataclass(slots=True)
class MCPServerConfig:
    """Connection config for one MCP server.

    For stdio transport set ``command`` (and optional ``args``/``env``).
    For SSE/HTTP transport set ``url``.
    """

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None


class _MCPSession(Protocol):
    """Minimal session surface the adapter depends on.

    Implementations expose discovered tools and an async ``call``. This keeps
    transport/loop management out of the adapter and makes the adapter testable
    with a plain in-memory fake.
    """

    @property
    def tools(self) -> list[Any]: ...

    def connect(self) -> None: ...

    async def call(self, name: str, arguments: dict[str, Any]) -> Any: ...

    def close(self) -> None: ...


class MCPAdapter(BaseAdapter):
    """CHP capability adapter that exposes an MCP server's tools.

    Each discovered MCP tool becomes a capability
    ``chp.adapters.mcp.<server>.<tool>`` whose ``input_schema`` is the tool's
    own JSON Schema (so chp-core's pre-invocation validation applies for free)
    and whose handler proxies to the live MCP session with full evidence.
    """

    adapter_category = "integration"
    adapter_tags = ["mcp"]

    def __init__(self, config: MCPServerConfig, *, session: _MCPSession | None = None) -> None:
        self._config = config
        self.adapter_id = f"chp.adapters.mcp.{config.name}"
        self.adapter_name = f"MCP: {config.name}"
        self.adapter_description = f"MCP server tools exposed as CHP capabilities ({config.name})."
        self._session: _MCPSession = session if session is not None else _ThreadedMCPSession(config)
        self._connected = False

    # -- CapabilityAdapter surface -----------------------------------------

    def capabilities(self):
        self._ensure_connected()
        for tool in self._session.tools:
            yield HostedCapability(
                descriptor=self._descriptor_for(tool),
                handler=self._make_handler(tool.name),
            )

    def close(self) -> None:
        """Tear down the underlying session. The host owns lifecycle."""
        self._session.close()
        self._connected = False

    # -- internals ----------------------------------------------------------

    def _ensure_connected(self) -> None:
        if not self._connected:
            self._session.connect()
            self._connected = True

    def _descriptor_for(self, tool: Any) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            id=f"chp.adapters.mcp.{self._config.name}.{tool.name}",
            version="1.0.0",
            description=getattr(tool, "description", None) or f"MCP tool {tool.name}",
            name=tool.name,
            category="integration",
            provider="mcp",
            risk="medium",
            input_schema=getattr(tool, "inputSchema", None) or {},
            tags=["mcp", self._config.name],
            emits=list(_EMITS),
        )

    def _make_handler(self, tool_name: str):
        server = self._config.name
        session = self._session

        async def handler(ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
            arguments = payload or {}
            start = time.monotonic()
            ctx.emit("mcp_tool_called", {
                "server": server,
                "tool": tool_name,
                "arg_keys": sorted(arguments.keys()),
            }, redacted=False)

            try:
                result = await session.call(tool_name, arguments)
            except Exception as exc:
                elapsed = round(time.monotonic() - start, 2)
                ctx.emit("mcp_error", {
                    "server": server,
                    "tool": tool_name,
                    "reason": type(exc).__name__,
                    "error": str(exc)[:MAX_ERROR_LEN],
                    "elapsed_s": elapsed,
                }, redacted=False)
                raise

            elapsed = round(time.monotonic() - start, 2)
            content = [_serialize_block(b) for b in (getattr(result, "content", None) or [])]
            is_error = bool(getattr(result, "isError", False))

            ctx.emit("mcp_tool_result", {
                "server": server,
                "tool": tool_name,
                "content_blocks": len(content),
                "is_error": is_error,
                "elapsed_s": elapsed,
            }, redacted=False)

            return {"content": content, "isError": is_error}

        return handler


def _serialize_block(block: Any) -> Any:
    """Convert an MCP content block to a JSON-safe dict."""
    if isinstance(block, dict):
        return block
    dump = getattr(block, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return {"type": "text", "text": str(block)}


class _ThreadedMCPSession:
    """Persistent MCP session on a dedicated background thread + event loop.

    The whole session lifecycle — opening the transport, initialize, list_tools,
    and final teardown — runs inside a single long-lived ``_serve`` task. This
    matters: anyio task groups / cancel scopes (used by ``stdio_client``) must be
    exited in the same task they were entered. Tool calls are dispatched onto the
    loop from the host's handler via ``run_coroutine_threadsafe`` and bridged back
    with ``asyncio.wrap_future``; the memory streams are safe to use from those
    sibling tasks because the loop is the same.
    """

    def __init__(self, config: MCPServerConfig) -> None:
        self._config = config
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"mcp-{config.name}",
            daemon=True,
        )
        self._ready = threading.Event()
        self._stop = asyncio.Event()
        self._error: Exception | None = None
        self._session: Any = None
        self._tools: list[Any] = []

    @property
    def tools(self) -> list[Any]:
        return self._tools

    def connect(self) -> None:
        self._thread.start()
        self._ready.wait()
        if self._error is not None:
            raise self._error

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        future = asyncio.run_coroutine_threadsafe(
            self._session.call_tool(name, arguments), self._loop
        )
        return await asyncio.wrap_future(future)

    def close(self) -> None:
        if not self._thread.is_alive():
            return
        self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(timeout=5)

    # -- background thread --------------------------------------------------

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        """Hold the MCP session open in a single task until close() is signalled."""
        from contextlib import AsyncExitStack

        try:
            from mcp import ClientSession
            async with AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(self._open_streams())
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                listed = await session.list_tools()
                self._tools = list(listed.tools)
                self._session = session
                self._ready.set()
                await self._stop.wait()  # contexts exit in THIS task on teardown
        except Exception as exc:  # surface to connect() caller
            self._error = exc
            self._ready.set()

    def _open_streams(self):
        cfg = self._config
        if cfg.url:
            from mcp.client.sse import sse_client
            return sse_client(cfg.url)
        if cfg.command:
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(command=cfg.command, args=cfg.args, env=cfg.env)
            return stdio_client(params)
        raise ValueError(f"MCPServerConfig {cfg.name!r} needs either 'command' (stdio) or 'url' (sse)")
