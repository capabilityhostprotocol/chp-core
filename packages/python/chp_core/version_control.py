"""Version-control governance capabilities for CHP development work."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

from .adapters import CapabilityAdapter, HostedCapability, register_adapter, register_hosted_capabilities
from .host import CapabilityExecutionContext, LocalCapabilityHost
from .types import CapabilityDescriptor, InvariantDescriptor, JSON, utc_now

DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
RADICLE_SENSITIVE_VALUE_FLAGS = {"--message", "-m", "--description", "-d"}


class GitAdapter(CapabilityAdapter):
    """Built-in adapter exposing Git version-control governance capabilities.

    Registered as the ``chp-git`` entry point under ``chp.adapters``.
    Discoverable via ``discover_adapters()`` and ``auto_register_adapters()``.
    """

    adapter_id = "chp.adapters.git"

    def capabilities(self) -> list[HostedCapability]:
        return git_capabilities()


class VersionControlAdapter(CapabilityAdapter):
    """Full adapter including both Git and Radicle capabilities.

    Used internally by the CHP development work host. Radicle capabilities
    are pre-built and available for programmatic invocation via
    ``host.invoke("chp.radicle.*", ...)`` when the ``rad`` CLI is installed.
    They are not exposed in the public CLI.
    """

    adapter_id = "chp.adapters.version_control"

    def capabilities(self) -> list[HostedCapability]:
        return [*git_capabilities(), *radicle_capabilities()]


def register_version_control_capabilities(host: LocalCapabilityHost) -> None:
    register_adapter(host, VersionControlAdapter())


def register_git_capabilities(host: LocalCapabilityHost) -> None:
    register_hosted_capabilities(host, git_capabilities())


def register_radicle_capabilities(host: LocalCapabilityHost) -> None:
    register_hosted_capabilities(host, radicle_capabilities())


def git_capabilities() -> list[HostedCapability]:
    return [
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.inspect_repo",
                version="0.1.0",
                description="Inspect local Git repository identity, branch, status, remotes, and Radicle hints.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "git"],
                emits=[
                    "execution_started",
                    "version_control_repo_inspected",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _inspect_repo,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.diff_summary",
                version="0.1.0",
                description="Summarize local Git changes without storing full patch content by default.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                        "include_patch": {"type": "boolean"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "git"],
                emits=[
                    "execution_started",
                    "version_control_diff_summarized",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _diff_summary,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.precommit_check",
                version="0.1.0",
                description="Run configured local pre-commit checks and record structured evidence.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                        "checks": {
                            "type": "array",
                            "items": {
                                "oneOf": [
                                    {"type": "string"},
                                    {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                ]
                            },
                        },
                        "timeout_seconds": {"type": "integer"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "git", "checks"],
                emits=[
                    "execution_started",
                    "version_control_precommit_checked",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _precommit_check,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.release_evidence_bundle",
                version="0.1.0",
                description="Generate a local version-control release evidence bundle.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                        "checks": {"type": "array"},
                        "work_correlation_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "release"],
                emits=[
                    "execution_started",
                    "version_control_release_bundle_generated",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _release_evidence_bundle,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.verify_merge_readiness",
                version="0.1.0",
                description="Verify local release evidence, checks, and approval before a merge.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "repo_root": {"type": "string"},
                        "checks": {"type": "array"},
                        "work_correlation_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "release_correlation_id": {"type": "string"},
                        "approval": {
                            "oneOf": [
                                {"type": "boolean"},
                                {"type": "object"},
                            ]
                        },
                        "require_approval": {"type": "boolean"},
                        "require_clean": {"type": "boolean"},
                        "timeout_seconds": {"type": "integer"},
                        "patch_id": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "release", "governance"],
                emits=[
                    "execution_started",
                    "version_control_merge_readiness_verified",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _verify_merge_readiness,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.version_bump",
                version="0.1.0",
                description=(
                    "Validate that pyproject.toml and package.json versions match, "
                    "then write the new version to both files."
                ),
                input_schema={
                    "type": "object",
                    "required": ["new_version"],
                    "properties": {
                        "repo_root": {"type": "string"},
                        "new_version": {"type": "string"},
                    },
                },
                output_schema={"type": "object"},
                tags=["chp", "development", "version-control", "release"],
                risk="medium",
                emits=[
                    "execution_started",
                    "version_bumped",
                    "execution_completed",
                    "execution_failed",
                ],
            ),
            _version_bump,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.rc_tag",
                version="0.1.0",
                description=(
                    "Create and push the next RC git tag (v{version}-rc.{n}) to origin. "
                    "Triggers CI + TestPyPI staging pipeline."
                ),
                input_schema={
                    "type": "object",
                    "required": ["version"],
                    "properties": {
                        "repo_root": {"type": "string"},
                        "version": {"type": "string"},
                        "allow_mutation": {"type": "boolean"},
                    },
                },
                output_schema={"type": "object"},
                invariants=[required_field_invariant("allow_mutation")],
                tags=["chp", "development", "version-control", "release"],
                risk="high",
                emits=[
                    "execution_started",
                    "rc_tag_pushed",
                    "execution_completed",
                    "execution_denied",
                    "execution_failed",
                ],
            ),
            _rc_tag,
        ),
        HostedCapability(
            CapabilityDescriptor(
                id="chp.version_control.release_tag",
                version="0.1.0",
                description=(
                    "Create and push the release git tag (v{version}) to origin. "
                    "Triggers PyPI + npm production publish via CI. "
                    "Requires release_bundle_correlation_id pointing to prior release evidence."
                ),
                input_schema={
                    "type": "object",
                    "required": ["version"],
                    "properties": {
                        "repo_root": {"type": "string"},
                        "version": {"type": "string"},
                        "release_bundle_correlation_id": {"type": "string"},
                        "allow_mutation": {"type": "boolean"},
                    },
                },
                output_schema={"type": "object"},
                invariants=[required_field_invariant("allow_mutation")],
                tags=["chp", "development", "version-control", "release"],
                risk="critical",
                emits=[
                    "execution_started",
                    "release_tag_pushed",
                    "execution_completed",
                    "execution_denied",
                    "execution_failed",
                ],
            ),
            _release_tag,
        ),
    ]


def radicle_capabilities() -> list[HostedCapability]:
    hosted: list[HostedCapability] = []
    for capability in [
        (
            "chp.radicle.identity",
            "Get Radicle identity through the local rad CLI.",
            _radicle_identity,
            "radicle_identity_inspected",
            "low",
            [],
        ),
        (
            "chp.radicle.repo_status",
            "Inspect Radicle repository status through the local rad CLI.",
            _radicle_repo_status,
            "radicle_repo_status_inspected",
            "low",
            [],
        ),
        (
            "chp.radicle.patches.list",
            "List Radicle patches through the local rad CLI.",
            _radicle_patches_list,
            "radicle_patches_listed",
            "low",
            [],
        ),
        (
            "chp.radicle.patches.inspect",
            "Inspect a Radicle patch through the local rad CLI.",
            _radicle_patch_inspect,
            "radicle_patch_inspected",
            "low",
            [],
        ),
        (
            "chp.radicle.patches.comment",
            "Comment on a Radicle patch with explicit mutation approval.",
            _radicle_patch_comment,
            "radicle_patch_commented",
            "high",
            [required_field_invariant("allow_mutation")],
        ),
        (
            "chp.radicle.patches.merge_dry_run",
            "Dry-run a Radicle patch merge through the local rad CLI.",
            _radicle_patch_merge_dry_run,
            "radicle_patch_merge_checked",
            "medium",
            [],
        ),
        (
            "chp.radicle.patches.merge",
            "Merge a Radicle patch with explicit mutation approval.",
            _radicle_patch_merge,
            "radicle_patch_merged",
            "critical",
            [required_field_invariant("allow_mutation")],
        ),
        (
            "chp.radicle.issues.list",
            "List Radicle issues through the local rad CLI.",
            _radicle_issues_list,
            "radicle_issues_listed",
            "low",
            [],
        ),
        (
            "chp.radicle.issues.inspect",
            "Inspect a Radicle issue through the local rad CLI.",
            _radicle_issue_inspect,
            "radicle_issue_inspected",
            "low",
            [],
        ),
        (
            "chp.radicle.issues.open",
            "Open a new Radicle issue with explicit mutation approval.",
            _radicle_issue_open,
            "radicle_issue_opened",
            "high",
            [required_field_invariant("allow_mutation")],
        ),
        (
            "chp.radicle.issues.comment",
            "Comment on a Radicle issue with explicit mutation approval.",
            _radicle_issue_comment,
            "radicle_issue_commented",
            "high",
            [required_field_invariant("allow_mutation")],
        ),
        (
            "chp.radicle.issues.state",
            "Change a Radicle issue state (open/closed) with explicit mutation approval.",
            _radicle_issue_state,
            "radicle_issue_state_changed",
            "high",
            [required_field_invariant("allow_mutation")],
        ),
    ]:
        capability_id, description, handler, event_type, risk, invariants = capability
        hosted.append(
            HostedCapability(
                CapabilityDescriptor(
                    id=capability_id,
                    version="0.1.0",
                    description=description,
                    input_schema={"type": "object"},
                    output_schema={"type": "object"},
                    invariants=invariants,
                    tags=["chp", "development", "version-control", "radicle", "experimental"],
                    risk=risk,  # type: ignore[arg-type]
                    emits=[
                        "execution_started",
                        event_type,
                        "execution_completed",
                        "execution_denied",
                        "execution_failed",
                    ],
                ),
                handler,
            )
        )
    return hosted


def required_field_invariant(field: str) -> InvariantDescriptor:
    return InvariantDescriptor(
        id=f"requires_{field}",
        kind="required_payload_fields",
        description=f"Requires explicit {field} in the invocation payload.",
        enforcement="host",
        failure_behavior="deny",
        parameters={"fields": [field]},
    )


async def _inspect_repo(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = resolve_repo_root(payload)
    result = inspect_git_repo(repo_root)
    ctx.emit(
        "version_control_repo_inspected",
        {
            "repo_root": result["repo_root"],
            "is_repo": result["is_repo"],
            "clean": result["clean"],
            "dirty_count": len(result["dirty_files"]),
            "untracked_count": len(result["untracked_files"]),
        },
    )
    return result


async def _diff_summary(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = resolve_repo_root(payload)
    result = summarize_git_diff(
        repo_root,
        include_patch=bool(payload.get("include_patch", False)),
    )
    ctx.emit(
        "version_control_diff_summarized",
        {
            "repo_root": result["repo_root"],
            "is_repo": result["is_repo"],
            "changed_file_count": result["changed_file_count"],
            "include_patch": result["include_patch"],
        },
    )
    return result


async def _precommit_check(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = resolve_repo_root(payload)
    result = run_precommit_checks(
        repo_root,
        payload.get("checks") or [],
        timeout_seconds=int(payload.get("timeout_seconds") or DEFAULT_COMMAND_TIMEOUT_SECONDS),
    )
    ctx.emit(
        "version_control_precommit_checked",
        {
            "repo_root": str(repo_root),
            "passed": result["passed"],
            "check_count": len(result["checks"]),
            "failed_count": len([check for check in result["checks"] if not check["passed"]]),
        },
    )
    return result


async def _release_evidence_bundle(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = resolve_repo_root(payload)
    bundle = build_release_evidence_bundle(
        repo_root,
        checks=payload.get("checks") or [],
        work_correlation_ids=[
            str(correlation_id)
            for correlation_id in payload.get("work_correlation_ids", [])
        ],
        host=ctx.host,
    )
    ctx.emit(
        "version_control_release_bundle_generated",
        {
            "repo_root": bundle["repo_root"],
            "passed": bundle["passed"],
            "check_count": len(bundle["checks"]),
            "work_trace_count": len(bundle["work_traces"]),
        },
    )
    return bundle


async def _verify_merge_readiness(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    repo_root = resolve_repo_root(payload)
    result = verify_merge_readiness(
        repo_root,
        checks=payload.get("checks") or [],
        work_correlation_ids=[
            str(correlation_id)
            for correlation_id in payload.get("work_correlation_ids", [])
        ],
        release_correlation_id=optional_payload_string(payload, "release_correlation_id"),
        approval=payload.get("approval"),
        require_approval=bool(payload.get("require_approval", False)),
        require_clean=bool(payload.get("require_clean", True)),
        timeout_seconds=int(payload.get("timeout_seconds") or DEFAULT_COMMAND_TIMEOUT_SECONDS),
        patch_id=optional_payload_string(payload, "patch_id"),
        host=ctx.host,
    )
    ctx.emit(
        "version_control_merge_readiness_verified",
        {
            "repo_root": result["repo_root"],
            "ready": result["ready"],
            "decision": result["decision"],
            "check_count": len(result["checks"]),
            "failed_count": len(result["failed_checks"]),
        },
    )
    return result


async def _version_bump(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    new_version = require_payload_value(payload, "new_version")
    repo_root = resolve_repo_root(payload)
    result = bump_version_files(repo_root, new_version)
    ctx.emit("version_bumped", {
        "old_version": result.get("old_version"),
        "new_version": result.get("new_version"),
        "passed": result.get("passed", False),
        "files_modified": result.get("files_modified", []),
    })
    return result


async def _rc_tag(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    version = require_payload_value(payload, "version")
    repo_root = resolve_repo_root(payload)
    remote = find_push_remote(repo_root)
    list_result = run_git(repo_root, ["tag", "--list", f"v{version}-rc.*"])
    existing_tags = [t.strip() for t in list_result.stdout.splitlines() if t.strip()]
    rc_nums = [int(m.group(1)) for t in existing_tags if (m := re.search(r"-rc\.(\d+)$", t))]
    next_rc = (max(rc_nums) + 1) if rc_nums else 1
    tag_name = f"v{version}-rc.{next_rc}"
    tag_result = run_git(repo_root, ["tag", tag_name])
    if tag_result.returncode != 0:
        ctx.emit("rc_tag_pushed", {"version": version, "tag": tag_name, "passed": False})
        return {"passed": False, "version": version, "tag": tag_name, "error": tag_result.stderr.strip()}
    push_result = run_git(repo_root, ["push", remote, tag_name])
    passed = push_result.returncode == 0
    ctx.emit("rc_tag_pushed", {"version": version, "tag": tag_name, "passed": passed, "pushed": passed, "remote": remote})
    return {"passed": passed, "version": version, "tag": tag_name, "pushed": passed, "remote": remote,
            "push_error": push_result.stderr.strip() if not passed else None}


async def _release_tag(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    version = require_payload_value(payload, "version")
    repo_root = resolve_repo_root(payload)
    remote = find_push_remote(repo_root)
    bundle_cid = optional_payload_string(payload, "release_bundle_correlation_id")
    if bundle_cid:
        events = ctx.host.replay(bundle_cid)
        if not events:
            return {"passed": False, "error": f"No release bundle evidence for correlation_id: {bundle_cid}"}
    tag_name = f"v{version}"
    tag_result = run_git(repo_root, ["tag", tag_name])
    if tag_result.returncode != 0:
        ctx.emit("release_tag_pushed", {"version": version, "tag": tag_name, "passed": False})
        return {"passed": False, "version": version, "tag": tag_name, "error": tag_result.stderr.strip()}
    push_result = run_git(repo_root, ["push", remote, tag_name])
    passed = push_result.returncode == 0
    ctx.emit("release_tag_pushed", {
        "version": version, "tag": tag_name, "passed": passed,
        "pushed": passed, "release_bundle_correlation_id": bundle_cid, "remote": remote,
    })
    return {"passed": passed, "version": version, "tag": tag_name, "pushed": passed,
            "release_bundle_correlation_id": bundle_cid, "remote": remote,
            "push_error": push_result.stderr.strip() if not passed else None}


def bump_version_files(repo_root: Path, new_version: str) -> JSON:
    pyproject = repo_root / "packages" / "python" / "pyproject.toml"
    package_json = repo_root / "packages" / "ts-types" / "package.json"
    errors: list[str] = []
    old_version: str | None = None

    py_content = pyproject.read_text()
    py_match = re.search(r'^version\s*=\s*"([^"]+)"', py_content, re.MULTILINE)
    if py_match:
        py_old = py_match.group(1)
        old_version = py_old
    else:
        errors.append("could not find version in pyproject.toml")

    pkg_content = package_json.read_text()
    pkg_match = re.search(r'"version"\s*:\s*"([^"]+)"', pkg_content)
    if pkg_match:
        pkg_old = pkg_match.group(1)
        if old_version is None:
            old_version = pkg_old
        elif old_version != pkg_old:
            errors.append(f"version mismatch: pyproject.toml={old_version}, package.json={pkg_old}")
    else:
        errors.append("could not find version in package.json")

    if errors:
        return {"passed": False, "error": "; ".join(errors), "old_version": old_version,
                "new_version": new_version, "files_modified": []}

    new_py = re.sub(r'^(version\s*=\s*)"[^"]+"', f'\\g<1>"{new_version}"', py_content, flags=re.MULTILINE)
    pyproject.write_text(new_py)
    new_pkg = re.sub(r'("version"\s*:\s*)"[^"]+"', f'\\g<1>"{new_version}"', pkg_content, count=1)
    package_json.write_text(new_pkg)
    return {
        "passed": True,
        "old_version": old_version,
        "new_version": new_version,
        "files_modified": [
            str(pyproject.relative_to(repo_root)),
            str(package_json.relative_to(repo_root)),
        ],
    }


async def _radicle_identity(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    result = inspect_radicle_identity(payload)
    ctx.emit(
        "radicle_identity_inspected",
        radicle_evidence_payload(result),
    )
    return result


async def _radicle_repo_status(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    result = run_radicle_operation(payload, ["status"], mutating=False)
    ctx.emit("radicle_repo_status_inspected", radicle_evidence_payload(result))
    return result


async def _radicle_patches_list(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    args = ["patch", "list"]
    state = str(payload.get("state") or "")
    if state and state != "all":
        args.append(f"--{state}")
    result = run_radicle_operation(payload, args, mutating=False)
    ctx.emit("radicle_patches_listed", radicle_evidence_payload(result))
    return result


async def _radicle_patch_inspect(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    patch_id = require_payload_value(payload, "patch_id")
    result = run_radicle_operation(payload, ["patch", "show", patch_id], mutating=False)
    ctx.emit("radicle_patch_inspected", radicle_evidence_payload(result, patch_id=patch_id))
    return result


async def _radicle_patch_comment(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    patch_id = require_payload_value(payload, "patch_id")
    body = require_payload_value(payload, "body")
    result = run_radicle_operation(
        payload,
        ["patch", "comment", patch_id, "--message", body],
        mutating=True,
    )
    ctx.emit("radicle_patch_commented", radicle_evidence_payload(result, patch_id=patch_id))
    return result


async def _radicle_patch_merge_dry_run(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    patch_id = require_payload_value(payload, "patch_id")
    args = ["patch", "merge", patch_id, "--dry-run"]
    revision = payload.get("revision")
    if revision:
        args.extend(["--revision", str(revision)])
    result = run_radicle_operation(payload, args, mutating=False)
    ctx.emit("radicle_patch_merge_checked", radicle_evidence_payload(result, patch_id=patch_id))
    return result


async def _radicle_patch_merge(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    patch_id = require_payload_value(payload, "patch_id")
    args = ["patch", "merge", patch_id]
    revision = payload.get("revision")
    if revision:
        args.extend(["--revision", str(revision)])
    result = run_radicle_operation(payload, args, mutating=True)
    ctx.emit("radicle_patch_merged", radicle_evidence_payload(result, patch_id=patch_id))
    return result


async def _radicle_issues_list(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    args = ["issue", "list"]
    state = str(payload.get("state") or "")
    if state and state != "all":
        args.append(f"--{state}")
    result = run_radicle_operation(payload, args, mutating=False)
    ctx.emit("radicle_issues_listed", radicle_evidence_payload(result))
    return result


async def _radicle_issue_inspect(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    issue_id = require_payload_value(payload, "issue_id")
    result = run_radicle_operation(payload, ["issue", "show", issue_id], mutating=False)
    ctx.emit("radicle_issue_inspected", radicle_evidence_payload(result, issue_id=issue_id))
    return result


async def _radicle_issue_open(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    title = require_payload_value(payload, "title")
    args = ["issue", "open", "--title", title]
    description = optional_payload_string(payload, "description")
    if description:
        args.extend(["--description", description])
    for label in (payload.get("labels") or []):
        args.extend(["--label", str(label)])
    result = run_radicle_operation(payload, args, mutating=True)
    ctx.emit("radicle_issue_opened", radicle_evidence_payload(result))
    return result


async def _radicle_issue_comment(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    issue_id = require_payload_value(payload, "issue_id")
    message = require_payload_value(payload, "message")
    result = run_radicle_operation(
        payload,
        ["issue", "comment", issue_id, "--message", message],
        mutating=True,
    )
    ctx.emit("radicle_issue_commented", radicle_evidence_payload(result, issue_id=issue_id))
    return result


async def _radicle_issue_state(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    require_mutation_allowed(payload)
    issue_id = require_payload_value(payload, "issue_id")
    state = require_payload_value(payload, "state")
    if state not in ("open", "closed"):
        raise ValueError(f"state must be 'open' or 'closed', got {state!r}")
    result = run_radicle_operation(payload, ["issue", "state", issue_id, state], mutating=True)
    ctx.emit("radicle_issue_state_changed", radicle_evidence_payload(result, issue_id=issue_id, state=state))
    return result


def resolve_repo_root(payload: JSON) -> Path:
    return Path(str(payload.get("repo_root") or ".")).resolve()


def inspect_git_repo(repo_root: Path) -> JSON:
    inside = run_git(repo_root, ["rev-parse", "--is-inside-work-tree"])
    is_repo = inside.returncode == 0 and inside.stdout.strip() == "true"
    if not is_repo:
        return {
            "repo_root": str(repo_root),
            "is_repo": False,
            "clean": False,
            "branch": None,
            "head": None,
            "top_level": None,
            "dirty_files": [],
            "untracked_files": [],
            "status": [],
            "remotes": [],
            "radicle_rids": [],
            "error": command_error(inside),
        }

    top_level = run_git(repo_root, ["rev-parse", "--show-toplevel"]).stdout.strip()
    branch = command_stdout_or_none(run_git(repo_root, ["branch", "--show-current"]))
    if not branch:
        branch = command_stdout_or_none(run_git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"]))
    head = command_stdout_or_none(run_git(repo_root, ["rev-parse", "HEAD"]))
    status = parse_porcelain(run_git(repo_root, ["status", "--porcelain=v1"]).stdout)
    remotes = parse_remotes(run_git(repo_root, ["remote", "-v"]).stdout)
    dirty_files = [entry["path"] for entry in status if entry["status"] != "??"]
    untracked_files = [entry["path"] for entry in status if entry["status"] == "??"]

    return {
        "repo_root": str(repo_root),
        "top_level": top_level or str(repo_root),
        "is_repo": True,
        "clean": len(status) == 0,
        "branch": branch,
        "head": head,
        "dirty_files": dirty_files,
        "untracked_files": untracked_files,
        "status": status,
        "remotes": remotes,
        "radicle_rids": discover_radicle_rids(remotes),
    }


def summarize_git_diff(repo_root: Path, *, include_patch: bool = False) -> JSON:
    repo = inspect_git_repo(repo_root)
    if not repo["is_repo"]:
        return {
            "repo_root": str(repo_root),
            "is_repo": False,
            "include_patch": include_patch,
            "changed_file_count": 0,
            "files": [],
            "totals": {"additions": 0, "deletions": 0},
            "patch": None,
            "error": repo.get("error"),
        }

    unstaged_numstat = parse_numstat(run_git(repo_root, ["diff", "--numstat"]).stdout, staged=False)
    staged_numstat = parse_numstat(run_git(repo_root, ["diff", "--cached", "--numstat"]).stdout, staged=True)
    files_by_path: dict[str, JSON] = {}
    for item in [*unstaged_numstat, *staged_numstat]:
        existing = files_by_path.setdefault(
            item["path"],
            {"path": item["path"], "additions": 0, "deletions": 0, "staged": False, "unstaged": False},
        )
        existing["additions"] += item["additions"] or 0
        existing["deletions"] += item["deletions"] or 0
        existing["staged"] = bool(existing["staged"] or item["staged"])
        existing["unstaged"] = bool(existing["unstaged"] or not item["staged"])

    for status_entry in repo["status"]:
        files_by_path.setdefault(
            status_entry["path"],
            {
                "path": status_entry["path"],
                "additions": 0,
                "deletions": 0,
                "staged": status_entry["status"][0] != "?" and status_entry["status"][0] != " ",
                "unstaged": status_entry["status"][1] != " " or status_entry["status"] == "??",
                "status": status_entry["status"],
            },
        )

    files = sorted(files_by_path.values(), key=lambda item: str(item["path"]))
    patch = None
    if include_patch:
        patch_result = run_git(repo_root, ["diff", "--patch", "--no-ext-diff"])
        patch = truncate(patch_result.stdout, 20000)

    return {
        "repo_root": str(repo_root),
        "is_repo": True,
        "include_patch": include_patch,
        "redacted_patch": not include_patch,
        "changed_file_count": len(files),
        "files": files,
        "totals": {
            "additions": sum(int(item.get("additions") or 0) for item in files),
            "deletions": sum(int(item.get("deletions") or 0) for item in files),
        },
        "patch": patch,
    }


def run_precommit_checks(
    repo_root: Path,
    checks: list[Any],
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> JSON:
    if not checks:
        return {
            "repo_root": str(repo_root),
            "passed": False,
            "checks": [
                {
                    "name": "checks_configured",
                    "command": [],
                    "returncode": 1,
                    "passed": False,
                    "stdout_preview": "",
                    "stderr_preview": "No checks configured.",
                }
            ],
        }

    results: list[JSON] = []
    for index, check in enumerate(checks, start=1):
        command = normalize_check_command(check)
        if not command:
            results.append(
                {
                    "name": f"check_{index}",
                    "command": [],
                    "returncode": 1,
                    "passed": False,
                    "stdout_preview": "",
                    "stderr_preview": "Empty check command.",
                }
            )
            continue
        try:
            completed = subprocess.run(
                command,
                cwd=repo_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            results.append(
                {
                    "name": f"check_{index}",
                    "command": command,
                    "returncode": completed.returncode,
                    "passed": completed.returncode == 0,
                    "stdout_preview": truncate(completed.stdout, 1000),
                    "stderr_preview": truncate(completed.stderr, 1000),
                }
            )
        except FileNotFoundError as exc:
            results.append(command_exception_result(index, command, exc))
        except subprocess.TimeoutExpired as exc:
            results.append(
                {
                    "name": f"check_{index}",
                    "command": command,
                    "returncode": 124,
                    "passed": False,
                    "stdout_preview": truncate(exc.stdout or "", 1000),
                    "stderr_preview": f"Timed out after {timeout_seconds} seconds.",
                }
            )

    return {
        "repo_root": str(repo_root),
        "passed": all(result["passed"] for result in results),
        "checks": results,
    }


def build_release_evidence_bundle(
    repo_root: Path,
    *,
    checks: list[Any],
    work_correlation_ids: list[str],
    host: LocalCapabilityHost,
) -> JSON:
    repo = inspect_git_repo(repo_root)
    diff = summarize_git_diff(repo_root)
    precommit = run_precommit_checks(repo_root, checks) if checks else None
    work_traces = [
        summarize_trace(host.replay(correlation_id), correlation_id)
        for correlation_id in work_correlation_ids
    ]
    bundle_checks = [
        {"name": "repo_inspected", "passed": bool(repo["is_repo"])},
        {"name": "worktree_clean", "passed": bool(repo.get("clean"))},
        {"name": "diff_summarized", "passed": diff.get("is_repo", False)},
    ]
    if precommit is not None:
        bundle_checks.append({"name": "precommit_checks", "passed": bool(precommit["passed"])})
    if work_correlation_ids:
        bundle_checks.append(
            {
                "name": "work_evidence_present",
                "passed": all(trace["event_count"] > 0 for trace in work_traces),
            }
        )

    return {
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "passed": all(check["passed"] for check in bundle_checks),
        "checks": bundle_checks,
        "repo": repo,
        "diff": diff,
        "precommit": precommit,
        "work_traces": work_traces,
    }


def verify_merge_readiness(
    repo_root: Path,
    *,
    checks: list[Any],
    work_correlation_ids: list[str],
    release_correlation_id: str | None,
    approval: Any,
    require_approval: bool,
    require_clean: bool,
    timeout_seconds: int,
    patch_id: str | None,
    host: LocalCapabilityHost,
) -> JSON:
    repo = inspect_git_repo(repo_root)
    diff = summarize_git_diff(repo_root)
    precommit = run_precommit_checks(repo_root, checks, timeout_seconds=timeout_seconds) if checks else None
    work_traces = [
        summarize_trace(host.replay(correlation_id), correlation_id)
        for correlation_id in work_correlation_ids
    ]
    release_trace = (
        summarize_trace(host.replay(release_correlation_id), release_correlation_id)
        if release_correlation_id
        else None
    )
    release_bundle_present = bool(
        release_trace
        and release_trace["event_count"] > 0
        and "chp.version_control.release_evidence_bundle" in release_trace["capability_ids"]
    )

    readiness_checks = [
        {"name": "repo_is_git_repo", "passed": bool(repo["is_repo"])},
        {
            "name": "worktree_clean",
            "passed": bool(repo.get("clean")) if require_clean else True,
            "required": require_clean,
        },
        {"name": "diff_summarized", "passed": bool(diff.get("is_repo", False))},
        {
            "name": "checks_passed",
            "passed": bool(precommit["passed"]) if precommit is not None else False,
            "required": bool(checks),
        },
    ]
    if work_correlation_ids:
        readiness_checks.append(
            {
                "name": "work_evidence_present",
                "passed": all(trace["event_count"] > 0 for trace in work_traces),
                "required": True,
            }
        )
    if release_correlation_id:
        readiness_checks.append(
            {
                "name": "release_evidence_present",
                "passed": release_bundle_present,
                "required": True,
            }
        )
    if require_approval:
        readiness_checks.append(
            {
                "name": "approval_present",
                "passed": approval_is_present(approval),
                "required": True,
            }
        )

    required_checks = [
        check
        for check in readiness_checks
        if check.get("required", True)
    ]
    failed_checks = [
        check["name"]
        for check in required_checks
        if not check["passed"]
    ]
    ready = not failed_checks

    return {
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "patch_id": patch_id,
        "ready": ready,
        "decision": "ready" if ready else "not_ready",
        "failed_checks": failed_checks,
        "checks": readiness_checks,
        "repo": repo,
        "diff": diff,
        "precommit": precommit,
        "work_traces": work_traces,
        "release_trace": release_trace,
        "approval": approval_summary(approval),
    }


def summarize_trace(events: list[JSON], correlation_id: str) -> JSON:
    return {
        "correlation_id": correlation_id,
        "event_count": len(events),
        "capability_ids": sorted({str(event.get("capability_id")) for event in events if event.get("capability_id")}),
        "event_types": [str(event.get("event_type")) for event in events],
        "outcomes": [event.get("outcome") for event in events if event.get("outcome") is not None],
    }


def approval_is_present(approval: Any) -> bool:
    if isinstance(approval, bool):
        return approval
    if isinstance(approval, dict):
        return approval.get("approved") is True
    return False


def approval_summary(approval: Any) -> JSON:
    if isinstance(approval, bool):
        return {"approved": approval}
    if isinstance(approval, dict):
        return {
            "approved": approval.get("approved") is True,
            "by": approval.get("by"),
            "reference": approval.get("reference"),
        }
    return {"approved": False}


def inspect_radicle_identity(payload: JSON) -> JSON:
    did_value, did = read_radicle_did(payload)
    if not did["available"] or did["returncode"] != 0:
        return did
    self_result = run_radicle_operation(payload, ["self"], mutating=False)
    return {
        "available": True,
        "passed": self_result["returncode"] == 0,
        "operation": "rad self",
        "returncode": self_result["returncode"],
        "did": did_value,
        "stdout_preview": self_result["stdout_preview"],
        "stderr_preview": self_result["stderr_preview"],
        "stdout_bytes": self_result.get("stdout_bytes", 0),
        "stderr_bytes": self_result.get("stderr_bytes", 0),
        "redacted_output": self_result.get("redacted_output", True),
    }


def run_radicle_operation(payload: JSON, args: list[str], *, mutating: bool) -> JSON:
    rad_path = str(payload.get("rad_path") or "rad")
    repo_root = Path(str(payload.get("repo_root") or ".")).resolve()
    timeout = int(payload.get("timeout_seconds") or 30)
    include_output = bool(payload.get("include_output", False))
    operation = safe_radicle_operation(args)
    try:
        completed = subprocess.run(
            [rad_path, *args],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=os.environ.copy(),
        )
    except FileNotFoundError:
        return {
            "available": False,
            "passed": False,
            "mutating": mutating,
            "operation": operation,
            "returncode": 127,
            "stdout_preview": "",
            "stderr_preview": f"Radicle CLI not found: {rad_path}",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "redacted_output": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "available": True,
            "passed": False,
            "mutating": mutating,
            "operation": operation,
            "returncode": 124,
            "stdout_preview": output_preview(stdout, include_output, 1000),
            "stderr_preview": f"Timed out after {timeout} seconds.",
            "stdout_bytes": output_length(stdout),
            "stderr_bytes": output_length(stderr),
            "redacted_output": not include_output,
        }

    return {
        "available": True,
        "passed": completed.returncode == 0,
        "mutating": mutating,
        "operation": operation,
        "returncode": completed.returncode,
        "stdout_preview": output_preview(completed.stdout, include_output, 4000),
        "stderr_preview": output_preview(completed.stderr, include_output, 4000),
        "stdout_bytes": output_length(completed.stdout),
        "stderr_bytes": output_length(completed.stderr),
        "redacted_output": not include_output,
    }


def radicle_evidence_payload(result: JSON, **extra: Any) -> JSON:
    return {
        **extra,
        "available": result.get("available", False),
        "passed": result.get("passed", False),
        "operation": result.get("operation"),
        "returncode": result.get("returncode"),
        "mutating": result.get("mutating", False),
        "redacted_output": result.get("redacted_output", True),
    }


def read_radicle_did(payload: JSON) -> tuple[str, JSON]:
    did = run_radicle_operation(
        {**payload, "include_output": True},
        ["self", "--did"],
        mutating=False,
    )
    did_value = str(did.get("stdout_preview") or "").strip()
    did["stdout_preview"] = ""
    did["stderr_preview"] = ""
    did["redacted_output"] = True
    return did_value, did


def safe_radicle_operation(args: list[str]) -> str:
    safe_args: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            safe_args.append("<redacted>")
            redact_next = False
            continue
        if any(arg.startswith(f"{flag}=") for flag in RADICLE_SENSITIVE_VALUE_FLAGS):
            flag = arg.split("=", 1)[0]
            safe_args.append(f"{flag}=<redacted>")
            continue
        safe_args.append(arg)
        if arg in RADICLE_SENSITIVE_VALUE_FLAGS:
            redact_next = True
    return " ".join(["rad", *safe_args])


def output_preview(value: str | bytes, include_output: bool, limit: int) -> str:
    if not include_output:
        return ""
    return truncate(value, limit)


def output_length(value: str | bytes) -> int:
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8"))


def require_payload_value(payload: JSON, field: str) -> str:
    value = payload.get(field)
    if value is None or value == "":
        raise ValueError(f"missing required payload field: {field}")
    return str(value)


def optional_payload_string(payload: JSON, field: str) -> str | None:
    value = payload.get(field)
    if value is None or value == "":
        return None
    return str(value)


def require_mutation_allowed(payload: JSON) -> None:
    if payload.get("allow_mutation") is not True:
        raise PermissionError("mutating version-control operations require allow_mutation=true")


def run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def find_push_remote(repo_root: Path) -> str:
    """Return the best remote name for tag pushes: prefer 'origin'/'github' (CI remotes), fall back to upstream."""
    for candidate in ("origin", "github"):
        check = run_git(repo_root, ["remote", "get-url", candidate])
        if check.returncode == 0:
            return candidate
    branch_result = run_git(repo_root, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if branch_result.returncode == 0:
        upstream = branch_result.stdout.strip()
        if "/" in upstream:
            return upstream.split("/", 1)[0]
    remotes_result = run_git(repo_root, ["remote"])
    remotes = [r.strip() for r in remotes_result.stdout.splitlines() if r.strip()]
    return remotes[0] if remotes else "origin"


def parse_porcelain(output: str) -> list[JSON]:
    entries: list[JSON] = []
    for line in output.splitlines():
        if not line:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        entries.append({"status": line[:2], "path": path, "raw": line})
    return entries


def parse_remotes(output: str) -> list[JSON]:
    remotes: dict[tuple[str, str], JSON] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, url, kind = parts[0], parts[1], parts[2].strip("()")
        remotes[(name, kind)] = {"name": name, "url": url, "kind": kind}
    return sorted(remotes.values(), key=lambda item: (item["name"], item["kind"]))


def discover_radicle_rids(remotes: list[JSON]) -> list[str]:
    rids: set[str] = set()
    for remote in remotes:
        url = str(remote.get("url") or "")
        if url.startswith("rad:"):
            rids.add(url)
        for token in url.replace("/", " ").split():
            if token.startswith("rad:"):
                rids.add(token)
    return sorted(rids)


def parse_numstat(output: str, *, staged: bool) -> list[JSON]:
    results: list[JSON] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        additions = None if parts[0] == "-" else int(parts[0])
        deletions = None if parts[1] == "-" else int(parts[1])
        path = parts[2]
        if len(parts) > 3:
            path = parts[-1]
        results.append(
            {
                "path": path,
                "additions": additions,
                "deletions": deletions,
                "staged": staged,
            }
        )
    return results


_CHECK_ALIASES: dict[str, list[str]] = {
    "tests": [
        "python", "-m", "pytest", "packages/python/tests/",
        "--ignore=packages/python/tests/test_stress.py",
        "-m", "not slow", "-q", "--no-cov",
    ],
    "alignment": ["python", "-m", "chp_core.cli", "work", "check-alignment", "--repo-root", "."],
}


def normalize_check_command(check: Any) -> list[str]:
    if isinstance(check, str):
        if check in _CHECK_ALIASES:
            return _CHECK_ALIASES[check]
        return shlex.split(check)
    if isinstance(check, list):
        return [str(part) for part in check]
    return []


def command_stdout_or_none(result: subprocess.CompletedProcess[str]) -> str | None:
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def command_error(result: subprocess.CompletedProcess[str]) -> JSON:
    return {
        "returncode": result.returncode,
        "stdout_preview": truncate(result.stdout, 1000),
        "stderr_preview": truncate(result.stderr, 1000),
    }


def command_exception_result(index: int, command: list[str], exc: Exception) -> JSON:
    return {
        "name": f"check_{index}",
        "command": command,
        "returncode": 127,
        "passed": False,
        "stdout_preview": "",
        "stderr_preview": str(exc),
    }


def truncate(value: str | bytes, limit: int) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if len(value) <= limit:
        return value
    return value[-limit:]
