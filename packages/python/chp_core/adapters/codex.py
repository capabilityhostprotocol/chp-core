"""CHP capability adapter for OpenAI Codex CLI tool calls and sessions.

Registers capability descriptors for Codex CLI built-in tools so they are
discoverable in host.discover() and can participate in CHP governance.

Handlers are no-ops: tool calls arrive via hooks (chp hook codex-post-tool),
not through LocalCapabilityHost.invoke().

Hook installation (add to ~/.codex/config.toml or equivalent):
    [hooks]
    post_tool_use = "chp hook codex-post-tool"
    stop          = "chp hook codex-stop"
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


class CodexAdapter(BaseAdapter):
    """Capability declarations for OpenAI Codex CLI built-in tools and sessions.

    Register this adapter on any host to make Codex capabilities
    discoverable and governable::

        register_adapter(host, CodexAdapter())
    """

    adapter_id = "codex"
    adapter_name = "OpenAI Codex CLI"
    adapter_description = "Evidence adapter for OpenAI Codex CLI tool calls and sessions."
    adapter_version = "1.0.0"
    adapter_tags = ["agentic", "codex", "openai"]
    adapter_category = "domain.agentic"

    def capabilities(self) -> Iterable[HostedCapability]:
        return [
            # --- Execution ---
            _cap("codex.shell", "Execute shell commands.", risk="medium", tags=["shell", "execution"]),

            # --- Filesystem reads ---
            _cap("codex.read", "Read a file.", risk="low", tags=["filesystem", "read"]),
            _cap("codex.ls", "List directory contents.", risk="low", tags=["filesystem", "read"]),
            _cap("codex.glob", "Search for files by glob (glob_file_search).", risk="low", tags=["filesystem", "search"]),
            _cap("codex.view_image", "Inspect an image at full resolution.", risk="low", tags=["vision", "read"]),

            # --- Filesystem writes ---
            # apply_patch is Codex's actual edit primitive (a single tool applying a colorized diff); the CLI
            # intercepts it internally. The old str_replace/create_file/delete_file names are legacy — kept
            # mapped below for continuity, but apply_patch is what the 2026 CLI emits.
            _cap("codex.apply_patch", "Apply a patch (add/update/delete files via a diff).", risk="medium",
                 tags=["filesystem", "write"]),
            _cap("codex.edit", "Edit a file (legacy str_replace).", risk="medium", tags=["filesystem", "write"]),
            _cap("codex.write", "Write a new file (legacy).", risk="medium", tags=["filesystem", "write"]),
            _cap("codex.delete", "Delete a file (legacy).", risk="high", tags=["filesystem", "write"]),

            # --- Planning ---
            _cap("codex.update_plan", "Maintain the step-by-step task plan.", risk="low", tags=["tasks"]),

            # --- Network ---
            _cap("codex.web_search", "Search the web.", risk="low", tags=["network"]),
            _cap("codex.web_fetch", "Fetch a URL.", risk="low", tags=["network"]),

            # --- MCP (generic) ---
            _cap("codex.mcp_tool", "Invoke an MCP server tool.", risk="medium", tags=["mcp"]),

            # --- Session lifecycle ---
            _cap(
                "codex.session",
                "Codex CLI session lifecycle (start/stop).",
                risk="low",
                tags=["session", "lifecycle"],
                emits=["session_completed"],
            ),
        ]
