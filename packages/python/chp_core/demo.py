"""Reusable demo host definition for CHP examples and CLI."""

from __future__ import annotations

from .capabilities import register_builtin_capabilities
from .decorators import capability
from .host import LocalCapabilityHost
from .store import SQLiteEvidenceStore
from .types import InvariantDescriptor


@capability(
    id="demo.search_information",
    version="0.1.0",
    description="Return deterministic search notes for a query.",
    input_schema={
        "type": "object",
        "required": ["query"],
        "properties": {"query": {"type": "string"}},
    },
    output_schema={"type": "object"},
    tags=["demo", "tool"],
)
def search_information(query: str):
    return {
        "query": query,
        "matches": [
            "MCP exposes tools to agents.",
            "CHP records capability execution evidence.",
            "They compose at the invocation boundary.",
        ],
    }


@capability(
    id="demo.deploy_preview",
    version="0.1.0",
    description="Pretend to deploy a preview when required context is present.",
    input_schema={
        "type": "object",
        "required": ["project", "environment"],
        "properties": {
            "project": {"type": "string"},
            "environment": {"type": "string"},
        },
    },
    output_schema={"type": "object"},
    invariants=[
        InvariantDescriptor(
            id="requires_project_and_environment",
            kind="required_payload_fields",
            description="Preview deployments require project and environment.",
            enforcement="host",
            failure_behavior="deny",
            parameters={"fields": ["project", "environment"]},
        )
    ],
    tags=["demo", "governance-ready"],
)
def deploy_preview(project: str, environment: str):
    return {
        "project": project,
        "environment": environment,
        "preview_url": f"https://preview.local/{project}/{environment}",
    }


def build_demo_host(store_path: str = ":memory:") -> LocalCapabilityHost:
    host = LocalCapabilityHost(
        "demo-http-capability-host",
        store=SQLiteEvidenceStore(store_path),
        metadata={
            "description": "CHP v0.1 demo host with HTTP discovery, invocation, and replay.",
            "transport": "http",
        },
    )
    register_builtin_capabilities(host)
    host.register(search_information)
    host.register(deploy_preview)
    return host
