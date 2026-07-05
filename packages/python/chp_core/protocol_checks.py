"""Protocol and launch messaging checks for CHP development."""

from __future__ import annotations

import re
import subprocess
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


def check_sync_integrity(repo_root: Path) -> JSON:
    """Check that chp-core's Python package is in sync with chp-dev source of truth."""
    checks: list[JSON] = []
    chp_dev_python = repo_root.parent / "chp-dev" / "packages" / "python" / "chp_core"
    chp_core_python = repo_root / "packages" / "python" / "chp_core"

    if not chp_dev_python.exists():
        add_check(
            checks,
            "chp_dev_sync_skipped",
            True,
            {"reason": "chp-dev not found as sibling — sync check skipped (CI environment)"},
        )
        return {"passed": True, "checks": checks, "skipped": True}

    result = subprocess.run(
        [
            "diff", "-rq",
            "--exclude=__pycache__", "--exclude=*.pyc", "--exclude=*.pyo",
            "--exclude=.chp",
            str(chp_dev_python), str(chp_core_python),
        ],
        capture_output=True,
        text=True,
    )
    diverged = [line for line in result.stdout.splitlines() if line]
    add_check(
        checks,
        "chp_dev_python_sync_clean",
        len(diverged) == 0,
        {
            "diverged_files": diverged[:10],
            "total_diverged": len(diverged),
            "hint": "run: bash scripts/sync-to-public.sh from chp-dev to resync",
        },
    )
    return {
        "passed": all(c["passed"] for c in checks),
        "checks": checks,
        "diverged_count": len(diverged),
    }


def check_registry_alignment(repo_root: Path) -> JSON:
    """Every adapter package present must have a registry/adapters.json entry.

    Subset-safe by design: it only asserts package -> entry, never the reverse.
    chp-dev has all 66 adapter packages; chp-core syncs a subset but the full
    registry — so "entry without package" is expected there and must not fail.
    The reverse (orphan-entry) drift is validated at the source by
    scripts/gen-registry.py --check.
    """
    checks: list[JSON] = []
    registry_path = repo_root / "registry" / "adapters.json"
    if not registry_path.exists():
        add_check(checks, "registry_skipped", True,
                  {"reason": "registry/adapters.json not present — skipped"})
        return {"passed": True, "checks": checks, "skipped": True}

    registry = read_json(registry_path)
    registered = {a.get("id") for a in registry.get("official", [])}
    pkg_ids = sorted(
        p.name for p in (repo_root / "packages").glob("chp-adapter-*") if p.is_dir()
    )
    unregistered = [pid for pid in pkg_ids if pid not in registered]
    add_check(
        checks,
        "registry_no_unregistered_adapters",
        len(unregistered) == 0,
        {
            "unregistered": unregistered[:10],
            "total_unregistered": len(unregistered),
            "hint": "run: python scripts/gen-registry.py to append, then assign category/tier/status",
        },
    )
    return {"passed": all(c["passed"] for c in checks), "checks": checks}


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

    # Published canonicalization vectors must still match what the code produces.
    # Non-Python verifiers pin these bytes; silent drift breaks cross-language interop.
    vec_dir = repo_root / "spec" / "test-vectors"
    if (vec_dir / "expected.json").exists():
        try:
            from .store import _compute_event_hash

            exp = read_json(vec_dir / "expected.json")
            ev = read_json(vec_dir / "event.json")["event"]
            recomputed = _compute_event_hash(ev, None)
            add_check(
                checks,
                "canonicalization_vectors_match",
                recomputed == exp["event_content_hash"],
                {"expected": exp["event_content_hash"], "recomputed": recomputed,
                 "hint": "canonicalization changed — regenerate spec/test-vectors/"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "canonicalization_vectors_match", False, {"error": str(exc)})

    # Governance vocabulary: the reserved denial registry, the schema examples,
    # the codes the runtime actually emits, and the normative spec MUST agree.
    from .types import DenialReason

    reserved = DenialReason.RESERVED_CODES
    host_src = read_text(repo_root / "packages" / "python" / "chp_core" / "host.py")
    emitted = set(re.findall(r'code="([a-z_]+)"', host_src)) | set(
        re.findall(r'"code": "([a-z_]+)"', host_src))
    add_check(
        checks,
        "denial_codes_runtime_reserved",
        emitted <= reserved,
        {"emitted_not_reserved": sorted(emitted - reserved), "hint":
         "host.py emits a bare code missing from DenialReason.RESERVED_CODES"},
    )
    denial_schema = read_json(repo_root / "schemas" / "denial-reason.schema.json")
    schema_examples = set(denial_schema["properties"]["code"].get("examples", []))
    add_check(
        checks,
        "denial_codes_schema_reserved",
        schema_examples == reserved,
        {"schema_only": sorted(schema_examples - reserved),
         "reserved_only": sorted(reserved - schema_examples)},
    )
    gov = read_text(repo_root / "spec" / "chp-governance-v0.2.md")
    add_check(
        checks,
        "governance_spec_names_denial_codes",
        all(f"`{c}`" in gov for c in reserved),
        {"missing": sorted(c for c in reserved if f"`{c}`" not in gov)},
    )
    add_check(
        checks,
        "governance_spec_names_risk_tiers",
        all(f"`{t}`" in gov for t in ("low", "medium", "high", "critical"))
        and "RISK_ORDER" in gov,
        {"path": "spec/chp-governance-v0.2.md"},
    )
    # The normative invocation pipeline must name every reserved denial code
    # (it's the authoritative trigger + ordering source per governance §2).
    pipeline_path = repo_root / "spec" / "chp-invocation-pipeline.md"
    if pipeline_path.exists():
        pipeline = read_text(pipeline_path)
        add_check(
            checks,
            "pipeline_spec_names_denial_codes",
            all(f"`{c}`" in pipeline for c in reserved),
            {"missing": sorted(c for c in reserved if f"`{c}`" not in pipeline)},
        )
    # Canonicalization golden set must recompute — chp-stable-v1 is
    # json.dumps(sort_keys=True); a second implementation pins to these bytes.
    canon_path = repo_root / "spec" / "test-vectors" / "canon" / "cases.json"
    if canon_path.exists():
        import json as _json

        canon = read_json(canon_path)
        drifted = [
            c["name"] for c in canon.get("cases", [])
            if _json.dumps(c["input"], sort_keys=True) != c["expected_canon"]
        ]
        add_check(
            checks,
            "canon_golden_set_recomputes",
            not drifted,
            {"drifted": drifted, "hint": "regenerate spec/test-vectors/canon/cases.json"},
        )

    sync = check_sync_integrity(repo_root)
    checks.extend(sync["checks"])

    registry = check_registry_alignment(repo_root)
    checks.extend(registry["checks"])

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
        "readme_governed_plane_positioning",
        # Guard the reinforced positioning: the governed, signed evidence PLANE
        # (not the old undersold "execution evidence layer"), while keeping the
        # "see what your agents did" hook.
        "the single signed plane" in readme
        and "governed evidence plane" in readme
        and "See what your agents and tools actually did" in readme,
        {"path": "README.md"},
    )
    add_check(
        checks,
        "quickstart_cli_first_controls",
        "chp-host serve" in quickstart
        and "chp-host init" in quickstart
        and "chp-host mesh" in quickstart,
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
