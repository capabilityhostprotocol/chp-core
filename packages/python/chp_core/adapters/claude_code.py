"""CHP capability adapter for Claude Code tool calls and sessions.

Registers capability descriptors for all Claude Code built-in tools so they
are discoverable in host.discover() and can participate in CHP governance
(invariants, risk tiers, policy declarations).

Handlers are no-ops: tool calls arrive via hooks (chp hook post-tool),
not through LocalCapabilityHost.invoke(). The adapter's value is schema
declaration and discoverability.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_core.adapters.claude_code import ClaudeCodeAdapter

    host = LocalCapabilityHost("my-host")
    register_adapter(host, ClaudeCodeAdapter())
    host.discover()  # now includes all claude_code.* capabilities
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from ..types import CapabilityDescriptor
from . import BaseAdapter, HostedCapability

CapabilityRisk = Literal["low", "medium", "high", "critical"]


def _noop(ctx, payload):  # noqa: ANN001
    return {}


def _cap(
    capability_id: str,
    description: str,
    risk: CapabilityRisk = "low",
    tags: list[str] | None = None,
    emits: list[str] | None = None,
) -> HostedCapability:
    return HostedCapability(
        descriptor=CapabilityDescriptor(
            id=capability_id,
            version="1.0.0",
            description=description,
            risk=risk,
            tags=tags or [],
            emits=emits or ["tool_use"],
            category="domain.agentic",
        ),
        handler=_noop,
    )


class ClaudeCodeAdapter(BaseAdapter):
    """Capability declarations for Claude Code built-in tools and sessions.

    Register this adapter on any host to make Claude Code capabilities
    discoverable and governable::

        register_adapter(host, ClaudeCodeAdapter())
    """

    adapter_id = "claude_code"
    adapter_name = "Claude Code"
    adapter_description = "Evidence adapter for Claude Code tool calls and sessions."
    adapter_version = "1.0.0"
    adapter_tags = ["agentic", "claude-code"]
    adapter_category = "domain.agentic"

    def capabilities(self) -> Iterable[HostedCapability]:
        return [
            # --- Execution ---
            _cap("claude_code.bash", "Execute shell commands.", risk="medium", tags=["shell", "execution"]),
            _cap("claude_code.agent", "Spawn a sub-agent.", risk="medium", tags=["agentic", "delegation"]),

            # --- Filesystem reads ---
            _cap("claude_code.read", "Read a file.", risk="low", tags=["filesystem", "read"]),
            _cap("claude_code.grep", "Search file contents.", risk="low", tags=["filesystem", "search"]),
            _cap("claude_code.glob", "List files by pattern.", risk="low", tags=["filesystem", "search"]),
            _cap("claude_code.ls", "List directory contents.", risk="low", tags=["filesystem", "read"]),
            _cap("claude_code.notebook_read", "Read a Jupyter notebook.", risk="low", tags=["filesystem", "read"]),

            # --- Filesystem writes ---
            _cap("claude_code.edit", "Edit a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("claude_code.write", "Write a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("claude_code.notebook_edit", "Edit a Jupyter notebook.", risk="medium", tags=["filesystem", "write"]),

            # --- Network ---
            _cap("claude_code.web_fetch", "Fetch a URL.", risk="low", tags=["network"]),
            _cap("claude_code.web_search", "Search the web.", risk="low", tags=["network"]),

            # --- Task management ---
            _cap("claude_code.todo_read", "Read the task list.", risk="low", tags=["tasks"]),
            _cap("claude_code.todo_write", "Update the task list.", risk="low", tags=["tasks"]),

            # --- MCP (generic) ---
            _cap("claude_code.mcp_tool", "Invoke an MCP server tool.", risk="medium", tags=["mcp"]),

            # --- Session lifecycle ---
            _cap(
                "claude_code.session",
                "Claude Code session lifecycle (start/stop).",
                risk="low",
                tags=["session", "lifecycle"],
                emits=["session_completed"],
            ),
        ]
