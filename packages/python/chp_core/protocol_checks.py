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
    # docs/onboarding.md graduated 2026-07-07: it now leads with the CURRENT
    # portable wizard (chp-host onboard); its mesh-oriented language paths are
    # labeled legacy inline, in their own section.
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

    # chp-jcs-v1 (proposal 0015): the second canonicalization must be defined in
    # the spec, its golden set must recompute byte-for-byte, and a chp-jcs-v1
    # signed bundle must verify through the dispatch seam — proving the
    # `canonicalization` field actually selects the serializer.
    spec_v02_text = read_text(repo_root / "spec" / "chp-v0.2.md")
    add_check(
        checks,
        "spec_defines_chp_jcs",
        "Second canonicalization (`chp-jcs-v1`)" in spec_v02_text
        and "dispatch seam" in spec_v02_text,
        {"hint": "spec/chp-v0.2.md §2 must register chp-jcs-v1 + the dispatch seam"},
    )
    jcs_cases = repo_root / "spec" / "test-vectors" / "canon" / "cases-jcs.json"
    if jcs_cases.exists():
        try:
            from .signing import _canon_jcs

            jc = read_json(jcs_cases)
            jcs_drift = [
                c["name"] for c in jc.get("cases", [])
                if _canon_jcs(c["input"]).decode("utf-8") != c["expected_canon"]
            ]
            add_check(
                checks,
                "jcs_canon_cases_verify",
                not jcs_drift,
                {"drifted": jcs_drift, "hint": "regenerate spec/test-vectors/canon/cases-jcs.json"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "jcs_canon_cases_verify", False, {"error": str(exc)})
    jcs_bundle = repo_root / "spec" / "test-vectors" / "signed-bundle-jcs.json"
    if jcs_bundle.exists():
        try:
            from .signing import verify_bundle

            jb = read_json(jcs_bundle)
            v = verify_bundle(jb)
            add_check(
                checks,
                "jcs_bundle_verifies",
                v.valid and jb.get("canonicalization") == "chp-jcs-v1",
                {"valid": v.valid, "hint": "regenerate signed-bundle-jcs.json"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "jcs_bundle_verifies", False, {"error": str(exc)})

    # Wire-version negotiation (spec §1.1, proposal 0016): the spec must define
    # the mechanism, and the reference descriptor must actually declare
    # supported_versions (else "declared" is a lie a client would trust).
    spec_v02_neg = read_text(repo_root / "spec" / "chp-v0.2.md")
    binding_text = read_text(repo_root / "spec" / "chp-http-binding.md")
    add_check(
        checks,
        "spec_defines_version_negotiation",
        "Version negotiation" in spec_v02_neg
        and "supported_versions" in spec_v02_neg
        and "X-CHP-Version" in binding_text,
        {"hint": "chp-v0.2.md §1.1 + chp-http-binding.md §2 must define the negotiation seam"},
    )
    try:
        from .types import HostDescriptor, negotiate_version

        d = HostDescriptor(id="align", protocol_version="0.2").to_dict()
        add_check(
            checks,
            "descriptor_declares_supported_versions",
            d.get("supported_versions") == ["0.1", "0.2"]
            and negotiate_version(["0.2"], d["supported_versions"]) == "0.2"
            and negotiate_version(["9.9"], d["supported_versions"]) is None,
            {"supported_versions": d.get("supported_versions")},
        )
    except Exception as exc:  # pragma: no cover - defensive
        add_check(checks, "descriptor_declares_supported_versions", False, {"error": str(exc)})

    # Schema $id consistency (proposal 0017): every schema's $id MUST sit on the
    # single canonical base https://chp.dev/schemas/v0.X/<filename>, and every
    # absolute $ref MUST resolve to a registered $id. The drift guard that did
    # not exist — it caught the two off-domain outliers.
    try:
        import re as _re

        schema_dir = repo_root / "schemas"
        id_re = _re.compile(r"^https://chp\.dev/schemas/v0\.\d+/[a-z0-9-]+\.schema\.json$")
        schema_ids: set[str] = set()
        bad_ids: list[str] = []
        for sf in sorted(schema_dir.glob("*.schema.json")):
            sid = read_json(sf).get("$id", "")
            schema_ids.add(sid)
            # the $id's filename segment must match the actual file
            if not id_re.match(sid) or not sid.endswith(f"/{sf.name}"):
                bad_ids.append(f"{sf.name} → {sid!r}")

        def _abs_refs(node: JSON) -> list[str]:
            out: list[str] = []
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "$ref" and isinstance(v, str) and v.startswith("http"):
                        out.append(v.split("#", 1)[0])
                    else:
                        out.extend(_abs_refs(v))
            elif isinstance(node, list):
                for v in node:
                    out.extend(_abs_refs(v))
            return out

        dangling: list[str] = []
        for sf in sorted(schema_dir.glob("*.schema.json")):
            for ref in _abs_refs(read_json(sf)):
                if ref not in schema_ids:
                    dangling.append(f"{sf.name} → {ref}")
        add_check(
            checks,
            "schema_ids_consistent",
            not bad_ids and not dangling,
            {"off_base": bad_ids, "dangling_refs": dangling,
             "hint": "every $id must be https://chp.dev/schemas/v0.X/<file>; every absolute $ref must match a registered $id"},
        )
    except Exception as exc:  # pragma: no cover - defensive
        add_check(checks, "schema_ids_consistent", False, {"error": str(exc)})

    # Non-omission / completeness (proposal 0018): the spec must define
    # chp-completeness-v1, and the completeness vector must verify with its
    # completeness self-check passing (the claim rides in the signed header).
    spec_v02_comp = read_text(repo_root / "spec" / "chp-v0.2.md")
    add_check(
        checks,
        "spec_defines_completeness",
        "chp-completeness-v1" in spec_v02_comp and "Non-omission" in spec_v02_comp,
        {"hint": "chp-v0.2.md §12 must register chp-completeness-v1"},
    )
    comp_vec = repo_root / "spec" / "test-vectors" / "signed-bundle-complete.json"
    if comp_vec.exists():
        try:
            from .signing import verify_bundle

            cb = read_json(comp_vec)
            v = verify_bundle(cb)
            add_check(
                checks,
                "completeness_vector_verifies",
                v.valid and v.checks.get("completeness") is True
                and (cb.get("completeness") or {}).get("scheme") == "chp-completeness-v1",
                {"valid": v.valid, "hint": "regenerate signed-bundle-complete.json"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "completeness_vector_verifies", False, {"error": str(exc)})

    # Anchors (spec §3.1): the anchored vector must still verify (guards the
    # omit-when-empty conditional in build/verify), and the spec must define
    # the anchor mechanism + the well-known route.
    anchored_path = repo_root / "spec" / "test-vectors" / "signed-bundle-anchored.json"
    if anchored_path.exists():
        try:
            from .signing import verify_bundle, _domain_anchor

            anchored = read_json(anchored_path)
            v = verify_bundle(anchored)
            add_check(
                checks,
                "anchored_vector_verifies",
                v.valid and _domain_anchor(anchored.get("host_identity") or {}) is not None,
                {"valid": v.valid, "hint": "regenerate signed-bundle-anchored.json"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "anchored_vector_verifies", False, {"error": str(exc)})
        spec_v02 = read_text(repo_root / "spec" / "chp-v0.2.md")
        add_check(
            checks,
            "spec_defines_anchors",
            "### 3.1 Anchors" in spec_v02
            and "/.well-known/chp-identity" in spec_v02
            and "Omit-when-empty" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Routing & reachability (§11, proposal 0003): the spec must define the
        # section, the transport denial code, and both reserved health events.
        add_check(
            checks,
            "spec_defines_routing",
            "## 11. Routing & Reachability" in spec_v02
            and "`host_unreachable`" in spec_v02
            and "host_marked_unhealthy" in spec_v02
            and "host_marked_healthy" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Witnessing (§12, proposal 0005): section, head scheme, statement kind,
        # and the retention dispositions that keep lawful lifecycle non-alarming.
        add_check(
            checks,
            "spec_defines_witnessing",
            "## 12. Witnessing" in spec_v02
            and "chp-store-head-v1" in spec_v02
            and "chain-witness" in spec_v02
            and "`purged`" in spec_v02
            and "`redacted`" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Idempotent replay (§13, proposal 0008): section, the key rule, the
        # serving-state stance, and the replayed marker.
        add_check(
            checks,
            "spec_defines_idempotency",
            "## 13. Reliability — Idempotent Replay" in spec_v02
            and "MUST NOT" in spec_v02
            and "serving state, never evidence" in spec_v02
            and '"replayed": true' in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Revocation (§10 Revocation, proposal 0007): statement kind, the
        # issuer-only rule's load-bearing phrase, and both routes.
        add_check(
            checks,
            "spec_defines_revocation",
            "mandate-revocation" in spec_v02
            and "issuer-only rule" in spec_v02
            and "POST /revocations" in spec_v02
            and "GET /revocations" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Sub-delegation (§10, proposal 0009): the section, the monotone
        # attenuation invariant, and the delegate-join binding.
        add_check(
            checks,
            "spec_defines_subdelegation",
            "**Sub-delegation**" in spec_v02
            and "attenuation" in spec_v02
            and "delegate join" in spec_v02
            and "NARROW scope and SHORTEN the window" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Revocation freshness (§12, proposal 0010): the digest scheme, the
        # dropped-revocation detection, and the mismatch code.
        add_check(
            checks,
            "spec_defines_revocation_freshness",
            "**Revocation freshness**" in spec_v02
            and "chp-revocation-head-v1" in spec_v02
            and "provable denial" in spec_v02
            and "revocation_head_mismatch" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Selective disclosure (§14, proposal 0011): the v2 hash scheme, the
        # commitment, and the withhold marker.
        add_check(
            checks,
            "spec_defines_selective_disclosure",
            "Selective Disclosure" in spec_v02
            and "chp-event-hash-v2" in spec_v02
            and "payload_commitment" in spec_v02
            and "chp_withheld" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Streaming completion (§13.1, proposal 0012): the chunk-seq digest, the
        # replay extension, and the resume header.
        add_check(
            checks,
            "spec_defines_streaming_replay",
            "Streaming replay" in spec_v02
            and "chp-chunk-seq-v1" in spec_v02
            and "Last-Event-ID" in spec_v02
            and "chunk_seq_digest" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Witness quorum + external anchoring (§12, proposal 0013).
        add_check(
            checks,
            "spec_defines_witness_quorum",
            "Witness quorum" in spec_v02
            and "chp-witness-quorum-v1" in spec_v02
            and "quorum_met" in spec_v02
            and "chp-store-head-anchor-v1" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )
        # Gateway exactly-once (§13.2, proposal 0014).
        add_check(
            checks,
            "spec_defines_gateway_exactly_once",
            "Gateway exactly-once" in spec_v02
            and "keyed by the client's" in spec_v02
            and "spans its owners" in spec_v02
            and "routes to no owner" in spec_v02,
            {"path": "spec/chp-v0.2.md"},
        )

    # The language-neutral reserved-names registry must match source — every
    # reserved denial code and evidence-type member appears in the generated doc.
    reserved_md = repo_root / "spec" / "reserved-names.md"
    if reserved_md.exists():
        doc = read_text(reserved_md)
        from . import types as _types

        missing: list[str] = [c for c in reserved if f"`{c}`" not in doc]
        for fam_name in dir(_types):
            if fam_name.endswith("_EVIDENCE_TYPES"):
                fam = getattr(_types, fam_name)
                if isinstance(fam, (set, frozenset)):
                    missing += [m for m in fam if f"`{m}`" not in doc]
        add_check(
            checks,
            "reserved_names_registry_current",
            not missing,
            {"missing": sorted(set(missing))[:10],
             "hint": "run: python scripts/gen-reserved-names.py"},
        )

    # The generated TS mirror must match source too — same rule, same fix.
    # (The legacy hand-written evidence.ts list is deprecated and unguarded.)
    reserved_ts = repo_root / "packages" / "ts-types" / "src" / "reserved.ts"
    if reserved_ts.exists():
        ts_doc = read_text(reserved_ts)
        from . import types as _types

        ts_missing: list[str] = [c for c in reserved if f'"{c}"' not in ts_doc]
        for fam_name in dir(_types):
            if fam_name.endswith("_EVIDENCE_TYPES"):
                fam = getattr(_types, fam_name)
                if isinstance(fam, (set, frozenset)):
                    if f"export const {fam_name}" not in ts_doc:
                        ts_missing.append(fam_name)
                    ts_missing += [m for m in fam if f'"{m}"' not in ts_doc]
        add_check(
            checks,
            "ts_reserved_names_current",
            not ts_missing,
            {"missing": sorted(set(ts_missing))[:10],
             "hint": "run: python scripts/gen-reserved-names.py"},
        )

    # Task-bundle vector must verify (guards the cross-host verification unit).
    task_vec = repo_root / "spec" / "test-vectors" / "task-bundle.json"
    if task_vec.exists():
        try:
            from .signing import verify_task_bundle

            tv = verify_task_bundle(read_json(task_vec))
            add_check(
                checks,
                "task_bundle_vector_verifies",
                tv.valid,
                {"checks": tv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "task_bundle_vector_verifies", False, {"error": str(exc)})

    # Aggregated task-bundle vector: aggregator signature + participation manifest.
    agg_vec = repo_root / "spec" / "test-vectors" / "task-bundle-aggregated.json"
    if agg_vec.exists():
        try:
            from .signing import verify_task_bundle

            av = verify_task_bundle(read_json(agg_vec))
            add_check(
                checks,
                "aggregated_task_bundle_vector_verifies",
                av.valid and av.checks.get("aggregator", False)
                and av.checks.get("participation", False),
                {"checks": av.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "aggregated_task_bundle_vector_verifies", False, {"error": str(exc)})

    # Adapter-provenance vector: the supply-chain statement verifies.
    prov_vec = repo_root / "spec" / "test-vectors" / "adapter-provenance.json"
    if prov_vec.exists():
        try:
            import hashlib

            from .signing import verify_provenance_statement

            pv = verify_provenance_statement(
                read_json(prov_vec),
                wheel_sha256=hashlib.sha256(b"chp fixture wheel bytes v1").hexdigest())
            add_check(
                checks,
                "provenance_vector_verifies",
                pv.valid,
                {"checks": pv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "provenance_vector_verifies", False, {"error": str(exc)})

    # Mandate vector: the delegated-authority statement verifies (§10).
    mandate_vec = repo_root / "spec" / "test-vectors" / "mandate.json"
    if mandate_vec.exists():
        try:
            from .signing import verify_mandate

            mandate = read_json(mandate_vec)
            mv = verify_mandate(
                mandate, at_time=mandate["valid_from"],
                capability_id="demo.echo",
                delegate_id=mandate["delegate_id"])
            add_check(
                checks,
                "mandate_vector_verifies",
                mv.valid,
                {"checks": mv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "mandate_vector_verifies", False, {"error": str(exc)})

    # Mandate-revocation vector: the withdrawal statement verifies AND actually
    # revokes the mandate vector (the issuer-only pair binding, §10).
    revocation_vec = repo_root / "spec" / "test-vectors" / "mandate-revocation.json"
    if revocation_vec.exists() and mandate_vec.exists():
        try:
            from .signing import verify_mandate as _vm
            from .signing import verify_mandate_revocation

            rev = read_json(revocation_vec)
            rv = verify_mandate_revocation(rev)
            mandate = read_json(mandate_vec)
            revoked = _vm(mandate, at_time=mandate["valid_from"], revocations=[rev])
            add_check(
                checks,
                "mandate_revocation_vector_verifies",
                rv.valid and not revoked.valid
                and revoked.checks.get("not_revoked") is False,
                {"statement": rv.checks, "pair_binding": revoked.checks,
                 "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "mandate_revocation_vector_verifies", False,
                      {"error": str(exc)})

    # Sub-mandate chain vector: the attenuated chain verifies end-to-end AND a
    # scope-widened tamper fails (proves attenuation binds; §10, proposal 0009).
    chain_vec = repo_root / "spec" / "test-vectors" / "mandate-chain.json"
    if chain_vec.exists():
        try:
            from .signing import mandate_root_principal
            from .signing import verify_mandate as _vmc

            sub = read_json(chain_vec)
            cv = _vmc(sub, at_time=sub["valid_from"], capability_id="demo.echo",
                      delegate_id=sub["delegate_id"])
            widened = read_json(chain_vec)
            widened["scope"] = ["chp.adapters.audit.*", "demo.echo"]  # broader than parent
            add_check(
                checks,
                "sub_mandate_vector_verifies",
                cv.valid and cv.checks.get("parent_valid") is True
                and mandate_root_principal(sub) == "vector-principal"
                and not _vmc(widened, at_time=sub["valid_from"]).valid,
                {"checks": cv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "sub_mandate_vector_verifies", False, {"error": str(exc)})

    # Chain-witness vector: the countersignature statement verifies (§12).
    witness_vec = repo_root / "spec" / "test-vectors" / "chain-witness.json"
    if witness_vec.exists():
        try:
            from .signing import verify_chain_witness

            wv = verify_chain_witness(
                read_json(witness_vec), expected_host_id="vector-witnessed-host")
            add_check(
                checks,
                "chain_witness_vector_verifies",
                wv.valid,
                {"checks": wv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "chain_witness_vector_verifies", False, {"error": str(exc)})

    # Revocation-freshness vector: the chain-witness carries a signed
    # revocation_head, and the freshness audit recomputes it from a matching
    # snapshot (§12, proposal 0010).
    revfresh_vec = repo_root / "spec" / "test-vectors" / "chain-witness-revfresh.json"
    if revfresh_vec.exists():
        try:
            from . import revocations as _revocations
            from .signing import verify_chain_witness as _vcw

            stmt = read_json(revfresh_vec)
            wv = _vcw(stmt, expected_host_id="vector-witnessed-host")
            ids = _revocations.revocation_ids(
                [{"mandate_id": "mnd_fixture0001",
                  "principal": {"public_key": "cvZ2Qm5jZml4dHVyZXB1YmtleXYx"}}],
                [{"revoked_key_id": "d20d8b42b94c3375"}])
            audit = _revocations.audit_revocation_freshness(
                [{"statement": stmt, "revocations": ids}], ids)
            add_check(
                checks,
                "revocation_head_vector_verifies",
                wv.valid and bool(stmt.get("revocation_head"))
                and audit["verdict"] == "fresh"
                and _revocations.compute_revocation_head(ids) == stmt["revocation_head"],
                {"checks": wv.checks, "audit": audit,
                 "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "revocation_head_vector_verifies", False, {"error": str(exc)})

    # Selective disclosure vectors (§14, proposal 0011): the withheld bundle
    # verifies (withheld event tolerated, disclosed event commitment-bound) and
    # the single v2 event recomputes to its published content_hash.
    withheld_vec = repo_root / "spec" / "test-vectors" / "bundle-withheld.json"
    v2_vec = repo_root / "spec" / "test-vectors" / "event-hash-v2.json"
    if withheld_vec.exists() and v2_vec.exists():
        try:
            from .signing import verify_bundle as _vb
            from .store import _compute_event_hash as _ceh

            wb = read_json(withheld_vec)
            bv = _vb(wb)
            solo = read_json(v2_vec)
            ev = dict(solo["event"])
            add_check(
                checks,
                "event_hash_v2_vector_verifies",
                bv.valid
                and bv.checks.get("payload_commitments") is True
                and wb["events"][0]["payload"] == {"chp_withheld": True}
                and wb["events"][1]["payload"] != {"chp_withheld": True}
                and _ceh(ev, solo.get("prev_hash")) == solo["content_hash"],
                {"checks": bv.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "event_hash_v2_vector_verifies", False, {"error": str(exc)})

    # Streaming chunk-seq vector (§13.1, proposal 0012): the published deltas
    # recompute to the committed chp-chunk-seq-v1 digest.
    chunk_seq_vec = repo_root / "spec" / "test-vectors" / "chunk-seq.json"
    if chunk_seq_vec.exists():
        try:
            from .host import chunk_seq_digest as _csd

            cs = read_json(chunk_seq_vec)
            add_check(
                checks,
                "chunk_seq_vector_verifies",
                _csd(cs["deltas"]) == cs["chunk_seq_digest"],
                {"hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "chunk_seq_vector_verifies", False, {"error": str(exc)})

    # Witness quorum + anchor vectors (§12, proposal 0013).
    quorum_vec = repo_root / "spec" / "test-vectors" / "witness-quorum.json"
    anchor_vec = repo_root / "spec" / "test-vectors" / "store-head-anchor.json"
    if quorum_vec.exists():
        try:
            from .witnessing import evaluate_witness_quorum

            q = read_json(quorum_vec)
            res = evaluate_witness_quorum(q["statements"], host_id=q["host_id"],
                                          sequence=q["sequence"], store_head=q["store_head"],
                                          k=q["k"])
            add_check(
                checks,
                "witness_quorum_vector_verifies",
                res["verdict"] == q["expected_verdict"]
                and res["distinct"] == q["expected_distinct"],
                {"result": res, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "witness_quorum_vector_verifies", False, {"error": str(exc)})
    if anchor_vec.exists():
        try:
            from .signing import verify_store_head_anchor

            anchor_v = verify_store_head_anchor(read_json(anchor_vec))
            add_check(
                checks,
                "store_head_anchor_vector_verifies",
                anchor_v.valid and anchor_v.checks.get("anchor") is True,
                {"checks": anchor_v.checks, "hint": "regenerate via scripts/gen-test-vectors.py"},
            )
        except Exception as exc:  # pragma: no cover - defensive
            add_check(checks, "store_head_anchor_vector_verifies", False, {"error": str(exc)})

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
