"""Codex self-observation helpers for dogfooding CHP."""

from __future__ import annotations

from .host import CapabilityExecutionContext, LocalCapabilityHost
from .types import CapabilityDescriptor, JSON

CODEX_CAPABILITY_IDS = [
    "codex.inspect_repository",
    "codex.modify_file",
    "codex.run_tests",
    "codex.write_spec",
    "codex.compare_framework",
    "codex.record_decision",
]


async def _record_codex_action(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    ctx.emit(
        "codex_action_recorded",
        {
            "task_intent": payload.get("task_intent"),
            "files_inspected": payload.get("files_inspected", []),
            "files_changed": payload.get("files_changed", []),
            "commands_run": payload.get("commands_run", []),
            "tests_run": payload.get("tests_run", []),
            "outcome": payload.get("outcome"),
            "open_questions": payload.get("open_questions", []),
            "follow_up_actions": payload.get("follow_up_actions", []),
        },
    )
    return {
        "accepted": True,
        "recorded_action": ctx.envelope.capability_id,
        "correlation_id": ctx.correlation_id,
    }


def register_codex_observation_capabilities(host: LocalCapabilityHost) -> None:
    for capability_id in CODEX_CAPABILITY_IDS:
        if _has_capability(host, capability_id):
            continue
        host.register(
            CapabilityDescriptor(
                id=capability_id,
                version="0.1.0",
                description=f"Record Codex engineering action: {capability_id}.",
                tags=["codex", "self-observation"],
                emits=[
                    "execution_started",
                    "codex_action_recorded",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _record_codex_action,
        )


def record_codex_action(
    host: LocalCapabilityHost,
    capability_id: str,
    payload: JSON,
    *,
    correlation_id: str,
):
    register_codex_observation_capabilities(host)
    return host.invoke(
        capability_id=capability_id,
        payload=payload,
        correlation_id=correlation_id,
        subject={"id": "codex", "type": "agent"},
    )


def _has_capability(host: LocalCapabilityHost, capability_id: str) -> bool:
    return any(
        capability["id"] == capability_id
        for capability in host.discover().get("capabilities", [])
    )
