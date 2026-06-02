"""Development-work capabilities hosted by the CHP self-observation host."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .adapters import HostedCapability, register_adapter
from .conformance_matrix import CONFORMANCE_MATRIX_TARGETS, build_conformance_matrix
from .demo_validation import validate_endpoint_demo
from .evidence_quality import build_evidence_quality_audit
from .host import CapabilityExecutionContext, LocalCapabilityHost
from .protocol_checks import check_alignment, check_messaging
from .types import CapabilityDescriptor, JSON
from .work_inventory import build_agentic_capability_inventory


class DevelopmentWorkAdapter:
    """Adapter grouping CHP's local development-feedback capabilities."""

    adapter_id = "chp.development_work"

    def capabilities(self) -> Iterable[HostedCapability]:
        return development_capabilities()


def register_development_capabilities(host: LocalCapabilityHost) -> None:
    register_adapter(host, DevelopmentWorkAdapter())


def development_capabilities() -> list[HostedCapability]:
    return [
        HostedCapability(
            CapabilityDescriptor(
                id="chp.validate_demo",
                version="0.1.0",
                description="Validate a local CHP demo and emit structured validation evidence.",
                input_schema={
                    "type": "object",
                    "required": ["demo"],
                    "properties": {
                        "demo": {"type": "string", "enum": ["endpoint"]},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "validation"],
                emits=[
                    "execution_started",
                    "demo_validated",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _validate_demo,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.check_schema_spec_alignment",
                version="0.1.0",
                description="Check v0.1 spec, schemas, Python models, and TypeScript types for protocol drift.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "alignment"],
                emits=[
                    "execution_started",
                    "schema_spec_alignment_checked",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _check_schema_spec_alignment,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.check_launch_messaging",
                version="0.1.0",
                description="Check public launch docs for evidence-first positioning and overclaim drift.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "messaging"],
                emits=[
                    "execution_started",
                    "launch_messaging_checked",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _check_launch_messaging,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.inventory_agentic_capabilities",
                version="0.1.0",
                description="Return CHP capabilities that make agentic development observable and governable.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "include_planned": {"type": "boolean"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "inventory"],
                emits=[
                    "execution_started",
                    "agentic_capability_inventory_generated",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _inventory_agentic_capabilities,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.audit_evidence_quality",
                version="0.1.0",
                description="Audit an evidence trace for completeness, consistency, and redaction basics.",
                input_schema={
                    "type": "object",
                    "required": ["correlation_id"],
                    "properties": {
                        "correlation_id": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "evidence", "quality"],
                emits=[
                    "execution_started",
                    "evidence_quality_audited",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _audit_evidence_quality,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.run_conformance_matrix",
                version="0.1.0",
                description="Run a local CHP conformance matrix and emit structured pass/fail evidence.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                        "targets": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": CONFORMANCE_MATRIX_TARGETS,
                            },
                        },
                        "timeout_seconds": {"type": "integer"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "conformance", "quality"],
                emits=[
                    "execution_started",
                    "conformance_matrix_completed",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _run_conformance_matrix,
        ),
    ]


async def _validate_demo(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    demo = str(payload["demo"])
    if demo != "endpoint":
        raise ValueError(f"unsupported demo: {demo}")

    validation = validate_endpoint_demo()
    ctx.emit(
        "demo_validated",
        {
            "demo": demo,
            "passed": validation["passed"],
            "checks": validation["checks"],
            "target_correlation_id": validation["target_correlation_id"],
        },
    )
    return validation


async def _check_schema_spec_alignment(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = Path(str(payload.get("repo_root") or ".")).resolve()
    result = check_alignment(repo_root)
    ctx.emit(
        "schema_spec_alignment_checked",
        {
            "repo_root": str(repo_root),
            "passed": result["passed"],
            "check_count": len(result["checks"]),
        },
    )
    return result


async def _check_launch_messaging(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = Path(str(payload.get("repo_root") or ".")).resolve()
    result = check_messaging(repo_root)
    ctx.emit(
        "launch_messaging_checked",
        {
            "repo_root": str(repo_root),
            "passed": result["passed"],
            "check_count": len(result["checks"]),
        },
    )
    return result


async def _inventory_agentic_capabilities(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    include_planned = bool(payload.get("include_planned", True))
    inventory = build_agentic_capability_inventory(include_planned=include_planned)
    ctx.emit(
        "agentic_capability_inventory_generated",
        {
            "capability_count": inventory["capability_count"],
            "implemented_count": inventory["status_counts"].get("implemented", 0),
            "planned_count": inventory["status_counts"].get("planned", 0),
            "categories": inventory["categories"],
        },
    )
    return inventory


async def _audit_evidence_quality(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    target_correlation_id = str(payload["correlation_id"])
    audit = build_evidence_quality_audit(
        ctx.host.replay(target_correlation_id),
        target_correlation_id=target_correlation_id,
    )
    ctx.emit(
        "evidence_quality_audited",
        {
            "target_correlation_id": target_correlation_id,
            "passed": audit["passed"],
            "score": audit["score"],
            "check_count": len(audit["checks"]),
            "event_count": audit["event_count"],
        },
    )
    return audit


async def _run_conformance_matrix(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = Path(str(payload.get("repo_root") or ".")).resolve()
    matrix = build_conformance_matrix(
        repo_root,
        targets=[str(target) for target in payload.get("targets", [])],
        timeout_seconds=int(payload.get("timeout_seconds") or 120),
        host=ctx.host,
    )
    ctx.emit(
        "conformance_matrix_completed",
        {
            "repo_root": str(repo_root),
            "passed": matrix["passed"],
            "target_count": matrix["target_count"],
            "failed_targets": matrix["failed_targets"],
        },
    )
    return matrix
