"""CHP capability adapter for Google Gemini CLI tool calls and sessions.

Registers capability descriptors for Gemini CLI built-in tools so they are
discoverable in host.discover() and can participate in CHP governance.

Handlers are no-ops: tool calls arrive via hooks (chp hook gemini-post-tool),
not through LocalCapabilityHost.invoke().

Hook installation (add to ~/.gemini/settings.json or equivalent):
    {
      "hooks": {
        "PostToolUse": [{"hooks": [{"type": "command", "command": "chp hook gemini-post-tool"}]}],
        "Stop":        [{"hooks": [{"type": "command", "command": "chp hook gemini-stop"}]}]
      }
    }
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


class GeminiCLIAdapter(BaseAdapter):
    """Capability declarations for Google Gemini CLI built-in tools and sessions.

    Register this adapter on any host to make Gemini CLI capabilities
    discoverable and governable::

        register_adapter(host, GeminiCLIAdapter())
    """

    adapter_id = "gemini_cli"
    adapter_name = "Google Gemini CLI"
    adapter_description = "Evidence adapter for Google Gemini CLI tool calls and sessions."
    adapter_version = "1.0.0"
    adapter_tags = ["agentic", "gemini", "google"]
    adapter_category = "domain.agentic"

    def capabilities(self) -> Iterable[HostedCapability]:
        return [
            # --- Execution ---
            _cap("gemini.run_shell_command", "Execute shell commands.", risk="medium", tags=["shell", "execution"]),

            # --- Filesystem reads ---
            _cap("gemini.read_file", "Read a file.", risk="low", tags=["filesystem", "read"]),
            _cap("gemini.read_many_files", "Read multiple files.", risk="low", tags=["filesystem", "read"]),
            _cap("gemini.ls", "List directory contents.", risk="low", tags=["filesystem", "read"]),

            # --- Filesystem writes ---
            _cap("gemini.write_file", "Write a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("gemini.edit", "Edit a file (replace/str_replace).", risk="medium", tags=["filesystem", "write"]),
            _cap("gemini.move_file", "Move a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("gemini.copy_file", "Copy a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("gemini.delete", "Delete files or directories.", risk="high", tags=["filesystem", "write"]),

            # --- Network ---
            _cap("gemini.web_search", "Search the web.", risk="low", tags=["network"]),
            _cap("gemini.web_fetch", "Fetch a URL.", risk="low", tags=["network"]),

            # --- Notebooks ---
            _cap("gemini.notebook_run", "Run a notebook cell.", risk="medium", tags=["notebook"]),
            _cap("gemini.notebook_edit", "Edit a notebook cell.", risk="medium", tags=["notebook"]),

            # --- Memory ---
            _cap("gemini.save_memory", "Save information to agent memory.", risk="low", tags=["memory"]),

            # --- MCP (generic) ---
            _cap("gemini.mcp_tool", "Invoke an MCP server tool.", risk="medium", tags=["mcp"]),

            # --- Session lifecycle ---
            _cap(
                "gemini.session",
                "Gemini CLI session lifecycle (start/stop).",
                risk="low",
                tags=["session", "lifecycle"],
                emits=["session_completed"],
            ),
        ]
