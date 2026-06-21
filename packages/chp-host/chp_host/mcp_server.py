"""MCP stdio server for a CHP adapter host.

Starts a Model Context Protocol server over stdio. Each CHP capability
registered on the host becomes an MCP tool, resource (read-only caps), or
prompt (governed workflow templates) — using the full MCP primitive model.

Protocol alignment:
- Correlation: every tool call carries a per-call correlation_id linked to the
  MCP session via parent_correlation_id, making all tool calls in a session
  traceable as a causal tree via chp_tree.
- isError: tool failures/denials return CallToolResult(isError=True) so the
  LLM can distinguish recoverable errors from successful calls.
- Tool Annotations (MCP 2025-03-26): readOnlyHint, destructiveHint,
  idempotentHint derived from CHP capability metadata.
- Resources: read-only capabilities + evidence store exposed as chp:// URIs.
- Prompts: governed multi-step workflows as user-initiated prompt templates.
- Status gating: only expose capabilities at or above --min-status threshold.

Usage (from CLI):
    chp-host mcp --adapters git,github,planning,delegation,safety
    chp-host mcp --profile my-profile.json
    chp-host mcp --min-status certified
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    AnyUrl,
    CallToolResult,
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
    ToolAnnotations,
)

from chp_core import LocalCapabilityHost
from chp_core.types import CorrelationContext, new_id

logger = logging.getLogger(__name__)

_MAX_TEXT_LEN = 8_000  # truncate very large payloads to keep MCP responses lean

# Capability maturity filter — only expose caps at or above this rank.
_STATUS_ORDER: dict[str, int] = {
    "deprecated": -1,
    "draft": 0,
    "experimental": 1,
    "certified": 2,
}

# ---------------------------------------------------------------------------
# Synthetic meta tool
# ---------------------------------------------------------------------------

_META_TOOL_NAME = "chp_adapters_meta_info"
_META_TOOL = Tool(
    name=_META_TOOL_NAME,
    description=(
        "List all loaded CHP capabilities and their pinned versions. "
        "Call after session start to confirm the MCP server loaded fresh code."
    ),
    inputSchema={"type": "object", "properties": {}},
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)

# ---------------------------------------------------------------------------
# Governed workflow prompt templates
# ---------------------------------------------------------------------------

_PROMPTS = [
    Prompt(
        name="governed-commit",
        description="Stage files → precommit-check → commit with a Radicle issue ref.",
        arguments=[
            PromptArgument(name="files", description="Space-separated file paths to stage", required=True),
            PromptArgument(name="message", description="Commit message subject line", required=True),
            PromptArgument(name="issue_id", description="Radicle issue short hash (e.g. 48a6dad)", required=True),
        ],
    ),
    Prompt(
        name="release-readiness",
        description="git.status + safety.assess + recent evidence check → go/no-go report.",
        arguments=[
            PromptArgument(name="version", description="Target release version (e.g. 0.8.0)", required=True),
        ],
    ),
    Prompt(
        name="open-issue",
        description="Open a Radicle issue and return its ID for use in subsequent commits.",
        arguments=[
            PromptArgument(name="title", description="Issue title", required=True),
            PromptArgument(name="labels", description="Comma-separated labels (optional)", required=False),
        ],
    ),
    Prompt(
        name="repo-explore",
        description=(
            "Locate relevant files for a task using the FastContext scout subagent. "
            "Returns file:line citations. Call before reading files for exploration tasks."
        ),
        arguments=[
            PromptArgument(name="task", description="What to find (e.g. 'where is WAL pragma set?')", required=True),
            PromptArgument(name="repo_path", description="Absolute path to the repository root", required=True),
        ],
    ),
]

_PROMPT_TEMPLATES: dict[str, str] = {
    "governed-commit": (
        "Follow these steps in order:\n"
        "1. chp.adapters.git.precommit_check — must pass before proceeding\n"
        "2. chp.adapters.git.commit files=[{files}] message='{message} rad:{issue_id}'\n"
        "Report the commit SHA and evidence_ids from step 2."
    ),
    "release-readiness": (
        "Release readiness check for v{version}:\n"
        "1. chp.adapters.git.status — repo must be clean (no staged/unstaged changes)\n"
        "2. chp.adapters.safety.assess capability_id='chp.adapters.release.tag' — risk must be low\n"
        "3. Read chp://evidence/recent — verify no failures in last 50 events\n"
        "4. Report go/no-go with evidence. If no-go, list every blocking issue."
    ),
    "open-issue": (
        "Open a Radicle issue:\n"
        "1. chp.adapters.radicle.issue_open title='{title}' labels='{labels}'\n"
        "2. Return the new issue_id — it is needed as an issue reference in commits."
    ),
    "repo-explore": (
        "Use the scout to locate relevant files, then read only the cited locations:\n\n"
        "1. Call chp.adapters.scout.query  task='{task}'  repo_path='{repo_path}'\n"
        "2. For each citation in result.files: Read that file at the specified line_range only.\n"
        "3. Do NOT read files that were not cited. Do NOT run grep or bash find commands.\n"
        "4. If scout returns 0 files: fall back to filesystem.grep with a specific pattern.\n\n"
        "The scout runs FastContext (local 4B model, ~6 turns max). It returns compact "
        "file:line citations — use them as the ONLY basis for subsequent Read calls."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cap_id_to_tool_name(cap_id: str) -> str:
    """chp.adapters.git.status → chp_adapters_git_status"""
    return cap_id.replace(".", "_")


def _build_name_index(caps: list[dict[str, Any]]) -> dict[str, str]:
    """tool_name → cap_id; built at startup to avoid lossy reverse-replace."""
    return {_cap_id_to_tool_name(c["id"]): c["id"] for c in caps}


def _make_tool(cap: dict[str, Any]) -> Tool:
    cap_id = cap["id"]
    description = cap.get("description") or cap_id

    risk = cap.get("risk", "low")
    if risk and risk != "low":
        description = f"[risk:{risk}] {description}"

    # Surface output_schema when non-trivial
    out_schema = cap.get("output_schema")
    if out_schema and out_schema not in ({}, {"type": "object"}):
        description += f"\nReturns: {json.dumps(out_schema, separators=(',', ':'))}"

    side_effects: list[str] = cap.get("side_effects") or []
    idempotency: str = cap.get("idempotency") or "optional"
    safety: dict[str, Any] = cap.get("safety_hint") or {}

    annotations = ToolAnnotations(
        readOnlyHint=risk == "low" and not side_effects,
        destructiveHint=risk in ("high", "critical") or bool(safety.get("destructive")),
        idempotentHint=idempotency == "required",
        openWorldHint=True,
    )

    schema = cap.get("input_schema") or {"type": "object", "properties": {}}
    return Tool(
        name=_cap_id_to_tool_name(cap_id),
        description=description,
        inputSchema=schema,
        annotations=annotations,
    )


def _format_result(
    outcome: str,
    data: Any,
    error: Any,
    evidence_ids: list[str] | None = None,
) -> str:
    payload: dict[str, Any] = {"outcome": outcome}
    if data is not None:
        payload["data"] = data
    if error:
        payload["error"] = error
    if evidence_ids:
        payload["_evidence_ids"] = evidence_ids
    text = json.dumps(payload, indent=2, default=str)
    if len(text) > _MAX_TEXT_LEN:
        text = text[:_MAX_TEXT_LEN] + "\n… (truncated)"
    return text


def _filter_caps_by_status(
    caps: list[dict[str, Any]],
    min_status: str,
) -> list[dict[str, Any]]:
    min_rank = _STATUS_ORDER.get(min_status, 0)
    return [
        c for c in caps
        if _STATUS_ORDER.get(c.get("status", "draft"), 0) >= min_rank
    ]


# ---------------------------------------------------------------------------
# Server entrypoint
# ---------------------------------------------------------------------------


async def run_mcp_server(
    host: Any,
    server_name: str = "chp",
    min_status: str = "draft",
) -> None:
    """Run *host* as an MCP stdio server until stdin closes.

    *host* may be a ``LocalCapabilityHost`` (in-process) or a
    ``MultiHostRouter`` (routes to remote HTTP CHP hosts). The router case
    connects to all configured transports before snapshotting capabilities.
    """
    server = Server(server_name)

    # Connect router and populate routing table if host is a MultiHostRouter.
    if hasattr(host, "connect"):
        await host.connect()

    # Discover capabilities — sync for LocalCapabilityHost, async for MultiHostRouter.
    if inspect.iscoroutinefunction(host.discover):
        discovered = await host.discover()
    else:
        discovered = host.discover()
    all_caps: list[dict[str, Any]] = discovered.get("capabilities", [])
    caps = _filter_caps_by_status(all_caps, min_status)

    tools = [_META_TOOL] + [_make_tool(c) for c in caps]
    tool_index: dict[str, dict[str, Any]] = {c["id"]: c for c in caps}
    name_to_cap_id: dict[str, str] = _build_name_index(caps)

    # MCP session correlation ID — every tool call carries this as parent,
    # making the full session a traceable tree in chp_tree / chp_show.
    mcp_session_id = new_id("mcp-sess")

    logger.info(
        "chp-host mcp: %d capabilities as MCP tools (session=%s, min_status=%s)",
        len(caps), mcp_session_id, min_status,
    )

    # -----------------------------------------------------------------------
    # Tools
    # -----------------------------------------------------------------------

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        # Synthetic meta tool — answered inline, no ainvoke.
        if name == _META_TOOL_NAME:
            info = {c["id"]: c.get("version", "unknown") for c in caps}
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(
                    {"capabilities": info, "count": len(info), "session_id": mcp_session_id},
                    indent=2,
                ))],
            )

        cap_id = name_to_cap_id.get(name, name)
        if cap_id not in tool_index:
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(
                    {"outcome": "denied", "error": f"unknown capability: {cap_id!r}"},
                ))],
                isError=True,
            )

        # Thread the MCP session as the parent correlation so every tool call
        # in a session is linked into one traceable tree.
        correlation = CorrelationContext(
            correlation_id=new_id("corr"),
            parent_correlation_id=mcp_session_id,
        )

        result = await host.ainvoke(cap_id, arguments or {}, correlation=correlation)
        evidence_ids: list[str] = getattr(result, "evidence_ids", None) or []
        text = _format_result(
            result.outcome,
            result.data,
            getattr(result, "error", None),
            evidence_ids,
        )
        is_err = result.outcome in ("failure", "denied")
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            isError=is_err,
        )

    # -----------------------------------------------------------------------
    # Resources — read-only caps + evidence store
    # -----------------------------------------------------------------------

    read_only_caps = [
        c for c in caps
        if c.get("risk", "low") == "low" and not (c.get("side_effects") or [])
    ]

    @server.list_resources()
    async def list_resources() -> list[Resource]:
        fixed = [
            Resource(
                uri="chp://catalog",
                name="CHP Capability Catalog",
                description="All registered capabilities: id, version, risk, description.",
                mimeType="application/json",
            ),
            Resource(
                uri="chp://evidence/recent",
                name="Recent Evidence Events",
                description="Last 50 CHP evidence events from this session's store.",
                mimeType="application/json",
            ),
            Resource(
                uri="chp://session/current",
                name="Current MCP Session",
                description="MCP session metadata and session correlation ID.",
                mimeType="application/json",
            ),
        ]
        cap_resources = [
            Resource(
                uri=f"chp://capability/{c['id']}",
                name=c.get("name") or c["id"],
                description=c.get("description", ""),
                mimeType="application/json",
            )
            for c in read_only_caps
        ]
        return fixed + cap_resources

    @server.read_resource()
    async def read_resource(uri: AnyUrl) -> str:
        s = str(uri)

        if s == "chp://catalog":
            return json.dumps(
                [{"id": c["id"], "version": c.get("version"), "risk": c.get("risk", "low"),
                  "status": c.get("status", "draft"), "description": c.get("description", "")}
                 for c in caps],
                indent=2,
            )

        if s == "chp://evidence/recent":
            try:
                if hasattr(host, "store"):
                    events = host.store.query(limit=50)
                    return json.dumps(events, indent=2, default=str)
                else:
                    # Multi-host router: evidence is distributed across hosts.
                    return json.dumps({
                        "note": "Multi-host mode — evidence is distributed. "
                                "Use chp://evidence/correlation/<id> with a specific correlation ID.",
                        "hosts": list(getattr(host, "_descriptors", {}).keys()),
                    })
            except Exception as exc:
                return json.dumps({"error": str(exc)})

        if s == "chp://session/current":
            return json.dumps(
                {"session_id": mcp_session_id, "tool_manifest": [c["id"] for c in caps],
                 "capability_count": len(caps), "min_status": min_status},
                indent=2,
            )

        if s.startswith("chp://capability/"):
            cap_id = s.removeprefix("chp://capability/")
            if cap_id in tool_index:
                return json.dumps(tool_index[cap_id], indent=2, default=str)
            raise ValueError(f"unknown capability: {cap_id!r}")

        if s.startswith("chp://evidence/correlation/"):
            corr_id = s.removeprefix("chp://evidence/correlation/")
            try:
                if hasattr(host, "store"):
                    events = host.store.by_correlation(corr_id)
                elif hasattr(host, "replay"):
                    # MultiHostRouter fans out and merges evidence across all hosts.
                    events = await host.replay(corr_id)
                else:
                    events = []
                return json.dumps(events, indent=2, default=str)
            except Exception as exc:
                return json.dumps({"error": str(exc)})

        raise ValueError(f"unknown chp:// resource: {s!r}")

    # -----------------------------------------------------------------------
    # Prompts — governed workflow templates
    # -----------------------------------------------------------------------

    @server.list_prompts()
    async def list_prompts() -> list[Prompt]:
        return _PROMPTS

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
        if name not in _PROMPT_TEMPLATES:
            raise ValueError(f"unknown prompt: {name!r}")
        args = arguments or {}
        text = _PROMPT_TEMPLATES[name].format_map(
            {k: args.get(k, f"<{k}>") for k in [
                "files", "message", "issue_id", "version", "title", "labels", "task", "repo_path"
            ]}
        )
        return GetPromptResult(
            messages=[PromptMessage(role="user", content=TextContent(type="text", text=text))]
        )

    # -----------------------------------------------------------------------
    # Run
    # -----------------------------------------------------------------------

    async with stdio_server() as (read_stream, write_stream):
        init_opts = server.create_initialization_options()
        await server.run(read_stream, write_stream, init_opts)
