"""CLI-facing helpers for invoking the CHP development-work host."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .codex import record_codex_action
from .types import JSON
from .work_host import DEFAULT_WORK_STORE, build_work_host


def record_work_action(
    *,
    capability_id: str,
    task_intent: str,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
    files_inspected: list[str] | None = None,
    files_changed: list[str] | None = None,
    commands_run: list[str] | None = None,
    tests_run: list[str] | None = None,
    outcome: str = "success",
    open_questions: list[str] | None = None,
    follow_up_actions: list[str] | None = None,
):
    host = build_work_host(store_path)
    payload: JSON = {
        "task_intent": task_intent,
        "files_inspected": files_inspected or [],
        "files_changed": files_changed if files_changed is not None else detect_changed_files(),
        "commands_run": commands_run or [],
        "tests_run": tests_run or [],
        "outcome": outcome,
        "open_questions": open_questions or [],
        "follow_up_actions": follow_up_actions or [],
    }
    return record_codex_action(
        host,
        capability_id,
        payload,
        correlation_id=correlation_id,
    )


def replay_work(correlation_id: str, *, store_path: str = DEFAULT_WORK_STORE) -> JSON:
    return build_work_host(store_path).replay_result(correlation_id).to_dict()


def explain_work(correlation_id: str, *, store_path: str = DEFAULT_WORK_STORE) -> JSON:
    host = build_work_host(store_path)
    result = host.invoke(
        "explain_execution",
        {"correlation_id": correlation_id},
        correlation_id=f"{correlation_id}-explanation",
    )
    return result.to_dict()


def summarize_work(correlation_id: str, *, store_path: str = DEFAULT_WORK_STORE) -> JSON:
    events = build_work_host(store_path).replay(correlation_id)
    action_events = [
        event
        for event in events
        if event.get("event_type") == "codex_action_recorded"
    ]
    files_changed = sorted(
        {
            path
            for event in action_events
            for path in event.get("payload", {}).get("files_changed", [])
        }
    )
    commands_run = [
        command
        for event in action_events
        for command in event.get("payload", {}).get("commands_run", [])
    ]
    tests_run = [
        test
        for event in action_events
        for test in event.get("payload", {}).get("tests_run", [])
    ]
    outcomes = [
        event.get("payload", {}).get("outcome")
        for event in action_events
        if event.get("payload", {}).get("outcome")
    ]
    return {
        "correlation_id": correlation_id,
        "action_count": len(action_events),
        "event_count": len(events),
        "files_changed": files_changed,
        "commands_run": commands_run,
        "tests_run": tests_run,
        "outcomes": outcomes,
        "latest_outcome": outcomes[-1] if outcomes else None,
    }


def validate_demo(
    demo: str,
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.validate_demo",
        {"demo": demo},
        correlation_id=correlation_id,
    )


def check_schema_spec_alignment(
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
    repo_root: str = ".",
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.check_schema_spec_alignment",
        {"repo_root": repo_root},
        correlation_id=correlation_id,
    )


def check_launch_messaging(
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
    repo_root: str = ".",
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.check_launch_messaging",
        {"repo_root": repo_root},
        correlation_id=correlation_id,
    )


def inventory_agentic_capabilities(
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
    include_planned: bool = True,
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.inventory_agentic_capabilities",
        {"include_planned": include_planned},
        correlation_id=correlation_id,
    )


def audit_evidence_quality(
    target_correlation_id: str,
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.audit_evidence_quality",
        {"correlation_id": target_correlation_id},
        correlation_id=correlation_id,
    )


def run_conformance_matrix(
    *,
    correlation_id: str,
    store_path: str = DEFAULT_WORK_STORE,
    repo_root: str = ".",
    targets: list[str] | None = None,
    timeout_seconds: int = 120,
):
    host = build_work_host(store_path)
    return host.invoke(
        "chp.run_conformance_matrix",
        {
            "repo_root": repo_root,
            "targets": targets or [],
            "timeout_seconds": timeout_seconds,
        },
        correlation_id=correlation_id,
    )


def detect_changed_files(cwd: str | Path = ".") -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []

    changed: list[str] = []
    for line in completed.stdout.splitlines():
        if not line:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        changed.append(path)
    return sorted(set(changed))
