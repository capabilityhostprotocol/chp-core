"""Protocol and launch messaging checks for CHP development."""

from __future__ import annotations

import re
from pathlib import Path

from .checks import add_check, read_json, read_text, safe_check_name
from .types import JSON

CORE_OBJECTS = [
    "CapabilityDescriptor",
    "HostDescriptor",
    "InvocationEnvelope",
    "InvocationResult",
    "ExecutionEvidence",
    "CorrelationContext",
    "ReplayQuery",
    "ReplayResult",
]
CORE_OUTCOMES = ["success", "failure", "denied", "skipped"]
CORE_SCHEMA_FILES = {
    "CapabilityDescriptor": "schemas/capability-descriptor.schema.json",
    "HostDescriptor": "schemas/host-descriptor.schema.json",
    "InvocationEnvelope": "schemas/invocation-envelope.schema.json",
    "InvocationResult": "schemas/invocation-result.schema.json",
    "ExecutionEvidence": "schemas/evidence-event.schema.json",
    "CorrelationContext": "schemas/correlation-context.schema.json",
    "ReplayQuery": "schemas/replay-query.schema.json",
    "ReplayResult": "schemas/replay-result.schema.json",
}
PUBLIC_MESSAGING_FILES = [
    "README.md",
    "docs/quickstart.md",
    "docs/why-chp.md",
    "docs/comparisons/chp-vs-mcp.md",
    "docs/comparisons/chp-and-opentelemetry.md",
    "docs/comparisons/landscape.md",
    "docs/security/threat-model-v0.1.md",
    "docs/roadmap.md",
    "spec/chp-v0.1.md",
    "packages/python/README.md",
    "examples/capability-host-endpoint-demo/README.md",
    "examples/agent-operations-demo/README.md",
    "examples/codex-self-observation-demo/README.md",
    "examples/mcp-bridge-demo/README.md",
]
LEGACY_MESSAGING_FILES = [
    "docs/onboarding.md",
    "docs/transports/zenoh.md",
    "docs/agent-prompt.md",
    "docs/capability-lookup-prompt.md",
]
FORBIDDEN_PUBLIC_CLAIMS = [
    "CHP replaces MCP",
    "replaces workflow engines",
    "production compliance platform",
    "full AI governance",
    "enterprise compliance platform",
    "universal protocol for everything",
    "full governance on day one",
]


def check_alignment(repo_root: Path) -> JSON:
    checks: list[JSON] = []
    spec = read_text(repo_root / "spec" / "chp-v0.1.md")
    python_types = read_text(repo_root / "packages" / "python" / "chp_core" / "types.py")
    python_init = read_text(repo_root / "packages" / "python" / "chp_core" / "__init__.py")
    ts_types = read_text(repo_root / "packages" / "ts-types" / "src" / "v0_1.ts")

    for object_name in CORE_OBJECTS:
        add_check(
            checks,
            f"spec_names_{object_name}",
            object_name in spec,
            {"object": object_name},
        )
        schema_path = repo_root / CORE_SCHEMA_FILES[object_name]
        schema = read_json(schema_path)
        add_check(
            checks,
            f"schema_title_{object_name}",
            schema.get("title") == object_name,
            {"path": str(schema_path.relative_to(repo_root)), "title": schema.get("title")},
        )
        add_check(
            checks,
            f"python_model_{object_name}",
            bool(re.search(rf"^class {re.escape(object_name)}\b", python_types, re.MULTILINE)),
            {"object": object_name},
        )
        add_check(
            checks,
            f"typescript_type_{object_name}",
            f"interface {object_name}" in ts_types,
            {"object": object_name},
        )

    invocation_result_schema = read_json(repo_root / "schemas" / "invocation-result.schema.json")
    evidence_schema = read_json(repo_root / "schemas" / "evidence-event.schema.json")
    invocation_outcomes = invocation_result_schema["properties"]["outcome"]["enum"]
    evidence_outcomes = [
        outcome
        for outcome in evidence_schema["properties"]["outcome"]["enum"]
        if outcome is not None
    ]
    add_check(
        checks,
        "schema_outcomes_invocation_result",
        invocation_outcomes == CORE_OUTCOMES,
        {"outcomes": invocation_outcomes},
    )
    add_check(
        checks,
        "schema_outcomes_evidence",
        evidence_outcomes == CORE_OUTCOMES,
        {"outcomes": evidence_outcomes},
    )
    for outcome in CORE_OUTCOMES:
        add_check(
            checks,
            f"spec_outcome_{outcome}",
            f"`{outcome}`" in spec,
            {"outcome": outcome},
        )
    add_check(
        checks,
        "python_outcomes",
        all(f'"{outcome}"' in python_types for outcome in CORE_OUTCOMES)
        and "ExecutionOutcome = Literal" in python_types,
        {"outcomes": CORE_OUTCOMES},
    )
    add_check(
        checks,
        "typescript_outcomes",
        all(f'"{outcome}"' in ts_types for outcome in CORE_OUTCOMES)
        and "CHP_V0_1_OUTCOMES" in ts_types,
        {"outcomes": CORE_OUTCOMES},
    )
    add_check(
        checks,
        "no_legacy_public_python_aliases",
        "CapabilityHostDescriptor" not in python_init
        and "ExecutionEvidenceEvent" not in python_init
        and "CapabilityHostDescriptor" not in python_types
        and "ExecutionEvidenceEvent" not in python_types,
        {"forbidden": ["CapabilityHostDescriptor", "ExecutionEvidenceEvent"]},
    )

    return {
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "core_objects": CORE_OBJECTS,
        "outcomes": CORE_OUTCOMES,
    }


def check_messaging(repo_root: Path) -> JSON:
    checks: list[JSON] = []
    readme = read_text(repo_root / "README.md")
    quickstart = read_text(repo_root / "docs" / "quickstart.md")
    mcp = read_text(repo_root / "docs" / "comparisons" / "chp-vs-mcp.md")

    add_check(
        checks,
        "readme_evidence_first_positioning",
        "visible, replayable, and ready for governance" in readme
        and "See what your agents and tools actually did." in readme,
        {"path": "README.md"},
    )
    add_check(
        checks,
        "quickstart_cli_first_controls",
        "chp demo endpoint" in quickstart
        and "chp work check-alignment" in quickstart
        and "chp work validate-demo" in quickstart,
        {"path": "docs/quickstart.md"},
    )
    add_check(
        checks,
        "mcp_composition_positioning",
        "MCP" in mcp
        and "CHP" in mcp
        and ("compose" in mcp.lower() or "complement" in mcp.lower()),
        {"path": "docs/comparisons/chp-vs-mcp.md"},
    )

    for path in PUBLIC_MESSAGING_FILES:
        text = read_text(repo_root / path)
        claims = [
            claim
            for claim in FORBIDDEN_PUBLIC_CLAIMS
            if claim.lower() in text.lower()
        ]
        add_check(
            checks,
            f"no_public_overclaim_{safe_check_name(path)}",
            not claims,
            {"path": path, "claims": claims},
        )

    for path in LEGACY_MESSAGING_FILES:
        text = read_text(repo_root / path)
        first_lines = "\n".join(text.splitlines()[:8]).lower()
        add_check(
            checks,
            f"legacy_doc_labeled_{safe_check_name(path)}",
            "status: legacy" in first_lines
            or "not the chp v0.1 core protocol" in first_lines
            or "not required for chp v0.1" in first_lines,
            {"path": path},
        )

    return {
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "public_files": PUBLIC_MESSAGING_FILES,
        "legacy_files": LEGACY_MESSAGING_FILES,
        "forbidden_claims": FORBIDDEN_PUBLIC_CLAIMS,
    }
