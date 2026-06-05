"""CHP CLI work recording, version-control, and Radicle commands."""

from __future__ import annotations

import argparse
import subprocess

from ..types import JSON
from ..work import (
    DEFAULT_WORK_STORE,
    audit_evidence_quality,
    build_work_host,
    check_launch_messaging,
    check_schema_spec_alignment,
    explain_work,
    inventory_agentic_capabilities,
    record_work_action,
    replay_work,
    run_conformance_matrix,
    summarize_work,
    validate_demo,
)
from ._core import print_json


def add_work_record_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--intent", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--capability-id", default="codex.record_decision")
    parser.add_argument("--store", default=DEFAULT_WORK_STORE)
    parser.add_argument("--file-inspected", action="append", default=[])
    parser.add_argument("--file-changed", action="append")
    parser.add_argument("--command-run", action="append", default=[])
    parser.add_argument("--test-run", action="append", default=[])
    parser.add_argument("--outcome", default="success")
    parser.add_argument("--open-question", action="append", default=[])
    parser.add_argument("--follow-up", action="append", default=[])


def add_vc_common_args(parser: argparse.ArgumentParser, default_correlation_id: str) -> None:
    parser.add_argument("--correlation-id", default=default_correlation_id)
    parser.add_argument("--store", default=DEFAULT_WORK_STORE)
    parser.add_argument("--repo-root", default=".")


def add_radicle_common_args(parser: argparse.ArgumentParser, default_correlation_id: str) -> None:
    parser.add_argument("--correlation-id", default=default_correlation_id)
    parser.add_argument("--store", default=DEFAULT_WORK_STORE)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--rad-path", default="rad")
    parser.add_argument("--timeout-seconds", type=int, default=30)


def invoke_work_capability(
    capability_id: str,
    payload: JSON,
    args: argparse.Namespace,
    *,
    pass_field: str | None = None,
) -> int:
    result = build_work_host(args.store).invoke(
        capability_id,
        payload,
        correlation_id=args.correlation_id,
    )
    data = result.to_dict()
    print_json(data)
    if not result.success:
        return 1
    if pass_field:
        return 0 if bool(result.data.get(pass_field)) else 1
    return 0


def radicle_payload(args: argparse.Namespace) -> JSON:
    return {
        "repo_root": args.repo_root,
        "rad_path": args.rad_path,
        "timeout_seconds": args.timeout_seconds,
    }


def cmd_work_record(args: argparse.Namespace) -> int:
    result = record_work_action(
        capability_id=args.capability_id,
        task_intent=args.intent,
        correlation_id=args.correlation_id,
        store_path=args.store,
        files_inspected=args.file_inspected,
        files_changed=args.file_changed,
        commands_run=args.command_run,
        tests_run=args.test_run,
        outcome=args.outcome,
        open_questions=args.open_question,
        follow_up_actions=args.follow_up,
    )
    print_json(result.to_dict())
    return 0


def cmd_work_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("work run requires a command after --")

    completed = subprocess.run(command, capture_output=True, text=True)
    command_text = " ".join(command)
    outcome = args.outcome
    if outcome == "success" and completed.returncode != 0:
        outcome = "failure"

    result = record_work_action(
        capability_id=args.capability_id,
        task_intent=args.intent,
        correlation_id=args.correlation_id,
        store_path=args.store,
        files_inspected=args.file_inspected,
        files_changed=args.file_changed,
        commands_run=[*args.command_run, command_text],
        tests_run=args.test_run,
        outcome=outcome,
        open_questions=args.open_question,
        follow_up_actions=args.follow_up,
    )
    print_json(
        {
            "command": command,
            "returncode": completed.returncode,
            "stdout_preview": completed.stdout[-1000:],
            "stderr_preview": completed.stderr[-1000:],
            "recorded": result.to_dict(),
        }
    )
    return completed.returncode


def cmd_work_replay(args: argparse.Namespace) -> int:
    print_json(replay_work(args.correlation_id, store_path=args.store))
    return 0


def cmd_work_explain(args: argparse.Namespace) -> int:
    print_json(explain_work(args.correlation_id, store_path=args.store))
    return 0


def cmd_work_summary(args: argparse.Namespace) -> int:
    print_json(summarize_work(args.correlation_id, store_path=args.store))
    return 0


def cmd_work_validate_demo(args: argparse.Namespace) -> int:
    result = validate_demo(
        args.demo,
        correlation_id=args.correlation_id,
        store_path=args.store,
    )
    print_json(result.to_dict())
    return 0 if result.success and result.data.get("passed") else 1


def cmd_work_check_alignment(args: argparse.Namespace) -> int:
    result = check_schema_spec_alignment(
        correlation_id=args.correlation_id,
        store_path=args.store,
        repo_root=args.repo_root,
    )
    print_json(result.to_dict())
    return 0 if result.success and result.data.get("passed") else 1


def cmd_work_check_messaging(args: argparse.Namespace) -> int:
    result = check_launch_messaging(
        correlation_id=args.correlation_id,
        store_path=args.store,
        repo_root=args.repo_root,
    )
    print_json(result.to_dict())
    return 0 if result.success and result.data.get("passed") else 1


def cmd_work_inventory(args: argparse.Namespace) -> int:
    result = inventory_agentic_capabilities(
        correlation_id=args.correlation_id,
        store_path=args.store,
        include_planned=not args.implemented_only,
    )
    print_json(result.to_dict())
    return 0 if result.success else 1


def cmd_work_audit_evidence(args: argparse.Namespace) -> int:
    result = audit_evidence_quality(
        args.target_correlation_id,
        correlation_id=args.correlation_id,
        store_path=args.store,
    )
    print_json(result.to_dict())
    return 0 if result.success and result.data.get("passed") else 1


def cmd_work_conformance_matrix(args: argparse.Namespace) -> int:
    result = run_conformance_matrix(
        correlation_id=args.correlation_id,
        store_path=args.store,
        repo_root=args.repo_root,
        targets=args.target,
        timeout_seconds=args.timeout_seconds,
    )
    print_json(result.to_dict())
    return 0 if result.success and result.data.get("passed") else 1


def cmd_work_vc_inspect(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.version_control.inspect_repo",
        {"repo_root": args.repo_root},
        args,
        pass_field="is_repo",
    )


def cmd_work_vc_diff(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.version_control.diff_summary",
        {"repo_root": args.repo_root, "include_patch": args.include_patch},
        args,
        pass_field="is_repo",
    )


def cmd_work_vc_precommit(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.version_control.precommit_check",
        {
            "repo_root": args.repo_root,
            "checks": args.check,
            "timeout_seconds": args.timeout_seconds,
        },
        args,
        pass_field="passed",
    )


def cmd_work_vc_release_bundle(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.version_control.release_evidence_bundle",
        {
            "repo_root": args.repo_root,
            "checks": args.check,
            "work_correlation_ids": args.include_correlation,
        },
        args,
        pass_field="passed",
    )


def cmd_work_vc_merge_readiness(args: argparse.Namespace) -> int:
    payload: JSON = {
        "repo_root": args.repo_root,
        "checks": args.check,
        "work_correlation_ids": args.include_correlation,
        "require_approval": args.require_approval,
        "require_clean": not args.allow_dirty,
        "timeout_seconds": args.timeout_seconds,
    }
    if args.release_correlation_id:
        payload["release_correlation_id"] = args.release_correlation_id
    if args.patch_id:
        payload["patch_id"] = args.patch_id
    if args.approval:
        payload["approval"] = True
    return invoke_work_capability(
        "chp.version_control.verify_merge_readiness",
        payload,
        args,
        pass_field="ready",
    )


def cmd_work_vc_version_bump(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.version_control.version_bump",
        {"repo_root": args.repo_root, "new_version": args.new_version},
        args,
        pass_field="passed",
    )


def cmd_work_vc_rc_tag(args: argparse.Namespace) -> int:
    payload: JSON = {"repo_root": args.repo_root, "version": args.version}
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.version_control.rc_tag",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_vc_release_tag(args: argparse.Namespace) -> int:
    payload: JSON = {"repo_root": args.repo_root, "version": args.version}
    if args.release_bundle_correlation_id:
        payload["release_bundle_correlation_id"] = args.release_bundle_correlation_id
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.version_control.release_tag",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_identity(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.radicle.identity",
        radicle_payload(args),
        args,
        pass_field="passed",
    )


def cmd_work_radicle_repo_status(args: argparse.Namespace) -> int:
    return invoke_work_capability(
        "chp.radicle.repo_status",
        radicle_payload(args),
        args,
        pass_field="passed",
    )


def cmd_work_radicle_patches_list(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["state"] = args.state
    return invoke_work_capability(
        "chp.radicle.patches.list",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_patch_inspect(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["patch_id"] = args.patch_id
    return invoke_work_capability(
        "chp.radicle.patches.inspect",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_patch_comment(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["patch_id"] = args.patch_id
    payload["body"] = args.body
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.radicle.patches.comment",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_patch_merge_dry_run(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["patch_id"] = args.patch_id
    if args.revision:
        payload["revision"] = args.revision
    return invoke_work_capability(
        "chp.radicle.patches.merge_dry_run",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_patch_merge(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["patch_id"] = args.patch_id
    if args.revision:
        payload["revision"] = args.revision
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.radicle.patches.merge",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_issues_list(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["state"] = args.state
    return invoke_work_capability(
        "chp.radicle.issues.list",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_issue_inspect(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["issue_id"] = args.issue_id
    return invoke_work_capability(
        "chp.radicle.issues.inspect",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_issue_open(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["title"] = args.title
    if args.description:
        payload["description"] = args.description
    if args.labels:
        payload["labels"] = args.labels
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.radicle.issues.open",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_issue_comment(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["issue_id"] = args.issue_id
    payload["message"] = args.message
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.radicle.issues.comment",
        payload,
        args,
        pass_field="passed",
    )


def cmd_work_radicle_issue_state(args: argparse.Namespace) -> int:
    payload = radicle_payload(args)
    payload["issue_id"] = args.issue_id
    payload["state"] = args.state
    if args.allow_mutation:
        payload["allow_mutation"] = True
    return invoke_work_capability(
        "chp.radicle.issues.state",
        payload,
        args,
        pass_field="passed",
    )
