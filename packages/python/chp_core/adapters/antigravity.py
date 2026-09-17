"""CHP capability adapter for Google's Antigravity CLI tool calls and sessions.

Antigravity CLI (announced at Google I/O 2026) is a Go-based terminal coding agent that REPLACES the
Gemini CLI (individual-tier Gemini CLI access retired 2026-06-18). It keeps the features people relied on —
Agent Skills, Subagents, Extensions (now "plugins"), MCP servers — and adds a declarative safety-policy
engine plus PreToolUse/PostToolUse lifecycle hooks that govern every tool call regardless of source.

Like the other CLI adapters here, handlers are no-ops: tool calls arrive via hooks, not through
LocalCapabilityHost.invoke(). The value is schema declaration + discoverability + risk tiers, so a mesh can
GOVERN an Antigravity session with the same evidence/policy machinery as Claude Code / Codex.

Hook installation (Antigravity lifecycle hooks; verify exact syntax against antigravity.google/docs):
    PreToolUse  -> chp hook antigravity-pre-tool
    PostToolUse -> chp hook antigravity-post-tool
    Stop        -> chp hook antigravity-stop

NOTE ON TOOL NAMES: the exact literal builtin tool identifiers were not publicly documented at time of
writing, so the tool-name -> capability map is intentionally NOT hard-coded in hooks.py yet (unknown names
fall back to ``antigravity.tool.<name>`` and stay governed, just without a pre-assigned risk tier). The
capability ids below name the surface Antigravity is confirmed to expose; fill ANTIGRAVITY_TOOL_CAPABILITY_MAP
once the docs pin the emitted names.
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


class AntigravityAdapter(BaseAdapter):
    """Capability declarations for Google's Antigravity CLI (the Gemini CLI successor).

    Register this adapter on any host to make Antigravity capabilities discoverable and governable::

        register_adapter(host, AntigravityAdapter())
    """

    adapter_id = "antigravity"
    adapter_name = "Google Antigravity CLI"
    adapter_description = "Evidence adapter for Google Antigravity CLI tool calls and sessions (replaces Gemini CLI)."
    adapter_version = "1.0.0"
    adapter_tags = ["agentic", "antigravity", "google"]
    adapter_category = "domain.agentic"

    def capabilities(self) -> Iterable[HostedCapability]:
        return [
            # --- Execution (gated by Antigravity's confirm_run_command policy) ---
            _cap("antigravity.run_shell_command", "Execute shell commands.", risk="medium", tags=["shell", "execution"]),

            # --- Filesystem reads ---
            _cap("antigravity.read_file", "Read a file.", risk="low", tags=["filesystem", "read"]),
            _cap("antigravity.ls", "List directory contents.", risk="low", tags=["filesystem", "read"]),

            # --- Filesystem writes ---
            _cap("antigravity.write_file", "Write a file.", risk="medium", tags=["filesystem", "write"]),
            _cap("antigravity.edit", "Edit a file.", risk="medium", tags=["filesystem", "write"]),

            # --- Network ---
            _cap("antigravity.web_search", "Search the web.", risk="low", tags=["network"]),
            _cap("antigravity.web_fetch", "Fetch a URL.", risk="low", tags=["network"]),

            # --- Memory ---
            _cap("antigravity.save_memory", "Save information to agent memory.", risk="low", tags=["memory"]),

            # --- Agentic (retained + new) ---
            _cap("antigravity.subagent", "Spawn a subagent.", risk="medium", tags=["agentic", "delegation"]),
            _cap("antigravity.skill", "Invoke an Agent Skill.", risk="medium", tags=["agentic", "skill"]),
            _cap("antigravity.plugin", "Invoke an Antigravity plugin (extension).", risk="medium", tags=["agentic", "plugin"]),
            _cap("antigravity.mcp_tool", "Invoke an MCP server tool.", risk="medium", tags=["mcp"]),

            # --- Session lifecycle ---
            _cap(
                "antigravity.session",
                "Antigravity CLI session lifecycle (start/stop).",
                risk="low",
                tags=["session", "lifecycle"],
                emits=["session_completed"],
            ),
        ]
