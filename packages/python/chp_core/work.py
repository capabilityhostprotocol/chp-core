"""Compatibility facade for CHP development self-observation utilities."""

from __future__ import annotations

from .demo_validation import validate_endpoint_demo
from .evidence_quality import build_evidence_quality_audit
from .protocol_checks import check_alignment, check_messaging
from .work_api import (
    audit_evidence_quality,
    check_launch_messaging,
    check_schema_spec_alignment,
    detect_changed_files,
    explain_work,
    inventory_agentic_capabilities,
    record_work_action,
    replay_work,
    run_conformance_matrix,
    summarize_work,
    validate_demo,
)
from .work_capabilities import (
    DevelopmentWorkAdapter,
    development_capabilities,
    register_development_capabilities,
)
from .work_host import DEFAULT_WORK_STORE, build_work_host
from .work_inventory import (
    AGENTIC_DEVELOPMENT_CAPABILITIES,
    build_agentic_capability_inventory,
)

__all__ = [
    "AGENTIC_DEVELOPMENT_CAPABILITIES",
    "DEFAULT_WORK_STORE",
    "DevelopmentWorkAdapter",
    "audit_evidence_quality",
    "build_agentic_capability_inventory",
    "build_evidence_quality_audit",
    "build_work_host",
    "check_alignment",
    "check_launch_messaging",
    "check_messaging",
    "check_schema_spec_alignment",
    "detect_changed_files",
    "development_capabilities",
    "explain_work",
    "inventory_agentic_capabilities",
    "record_work_action",
    "register_development_capabilities",
    "replay_work",
    "run_conformance_matrix",
    "summarize_work",
    "validate_demo",
    "validate_endpoint_demo",
]
