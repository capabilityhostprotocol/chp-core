"""Local conformance matrix helpers for CHP development work."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .checks import preview_text
from .demo_validation import validate_endpoint_demo
from .host import LocalCapabilityHost
from .types import JSON, utc_now

CONFORMANCE_MATRIX_TARGETS = [
    "sample-passing",
    "sample-failing-no-evidence",
    "work-host",
    "endpoint-demo",
]


def build_conformance_matrix(
    repo_root: Path,
    *,
    targets: list[str],
    timeout_seconds: int,
    host: LocalCapabilityHost,
) -> JSON:
    selected_targets = select_conformance_targets(targets)
    target_results: list[JSON] = []

    for target in selected_targets:
        if target == "sample-passing":
            target_results.append(
                run_conformance_command_target(
                    repo_root,
                    target,
                    ["--sample", "passing"],
                    expect_success=True,
                    timeout_seconds=timeout_seconds,
                )
            )
        elif target == "sample-failing-no-evidence":
            target_results.append(
                run_conformance_command_target(
                    repo_root,
                    target,
                    ["--sample", "failing-no-evidence"],
                    expect_success=False,
                    timeout_seconds=timeout_seconds,
                )
            )
        elif target == "work-host":
            target_results.append(check_work_host_target(host))
        elif target == "endpoint-demo":
            target_results.append(check_endpoint_demo_target())
        else:
            raise ValueError(f"unknown conformance target: {target}")

    failed_targets = [
        str(result["target"])
        for result in target_results
        if not result["passed"]
    ]
    return {
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "passed": not failed_targets,
        "target_count": len(target_results),
        "failed_targets": failed_targets,
        "targets": target_results,
        "available_targets": CONFORMANCE_MATRIX_TARGETS,
    }


def select_conformance_targets(targets: list[str]) -> list[str]:
    if not targets:
        return list(CONFORMANCE_MATRIX_TARGETS)
    unknown = sorted(set(targets).difference(CONFORMANCE_MATRIX_TARGETS))
    if unknown:
        raise ValueError(f"unknown conformance target(s): {', '.join(unknown)}")
    return targets


def run_conformance_command_target(
    repo_root: Path,
    target: str,
    runner_args: list[str],
    *,
    expect_success: bool,
    timeout_seconds: int,
) -> JSON:
    runner = repo_root / "conformance" / "runner.py"
    command = [sys.executable, str(runner), *runner_args]
    if not runner.exists():
        return {
            "target": target,
            "kind": "conformance-runner",
            "passed": False,
            "expected_success": expect_success,
            "observed_success": False,
            "returncode": 127,
            "command": command,
            "stdout_preview": "",
            "stderr_preview": f"Missing conformance runner: {runner}",
        }
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "target": target,
            "kind": "conformance-runner",
            "passed": False,
            "expected_success": expect_success,
            "observed_success": False,
            "returncode": 124,
            "command": command,
            "stdout_preview": preview_text(exc.stdout or ""),
            "stderr_preview": f"Timed out after {timeout_seconds} seconds.",
        }

    observed_success = completed.returncode == 0
    return {
        "target": target,
        "kind": "conformance-runner",
        "passed": observed_success == expect_success,
        "expected_success": expect_success,
        "observed_success": observed_success,
        "returncode": completed.returncode,
        "command": command,
        "stdout_preview": preview_text(completed.stdout),
        "stderr_preview": preview_text(completed.stderr),
    }


def check_work_host_target(host: LocalCapabilityHost) -> JSON:
    descriptor = host.discover()
    capability_ids = {
        capability["id"]
        for capability in descriptor.get("capabilities", [])
    }
    required = {
        "trace_execution",
        "explain_execution",
        "evaluate_counterfactual",
        "chp.run_conformance_matrix",
        "chp.version_control.verify_merge_readiness",
    }
    missing = sorted(required.difference(capability_ids))
    return {
        "target": "work-host",
        "kind": "local-host",
        "passed": descriptor.get("protocol_version") == "0.1" and not missing,
        "protocol_version": descriptor.get("protocol_version"),
        "capability_count": len(capability_ids),
        "missing_capabilities": missing,
    }


def check_endpoint_demo_target() -> JSON:
    validation = validate_endpoint_demo()
    return {
        "target": "endpoint-demo",
        "kind": "http-demo",
        "passed": validation["passed"],
        "checks": validation["checks"],
        "target_correlation_id": validation["target_correlation_id"],
    }
