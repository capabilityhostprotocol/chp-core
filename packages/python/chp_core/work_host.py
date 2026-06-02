"""Local CHP development-work host composition."""

from __future__ import annotations

from .capabilities import register_builtin_capabilities
from .codex import register_codex_observation_capabilities
from .host import LocalCapabilityHost
from .store import SQLiteEvidenceStore
from .version_control import register_version_control_capabilities
from .work_capabilities import register_development_capabilities

DEFAULT_WORK_STORE = ".chp/codex-self-observation.sqlite"


def build_work_host(store_path: str = DEFAULT_WORK_STORE) -> LocalCapabilityHost:
    host = LocalCapabilityHost(
        "chp-development-work",
        store=SQLiteEvidenceStore(store_path),
        metadata={
            "description": "Local CHP self-observation host for development work.",
            "purpose": "development-feedback-loop",
        },
    )
    register_builtin_capabilities(host)
    register_codex_observation_capabilities(host)
    register_development_capabilities(host)
    register_version_control_capabilities(host)
    return host
