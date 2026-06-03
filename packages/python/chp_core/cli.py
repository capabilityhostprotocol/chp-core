"""Command-line interface for the CHP reference host."""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
from typing import Any
from urllib.request import Request, urlopen

from .demo import build_demo_host
from .http import create_http_server, serve_http
from .types import JSON
from .work import (
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chp",
        description="CHP v0.1 local host utilities.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    host = subcommands.add_parser("host", help="Read a served host descriptor.")
    host.add_argument("--url", default="http://127.0.0.1:8765")
    host.set_defaults(func=cmd_host)

    serve_demo = subcommands.add_parser("serve-demo", help="Serve the built-in demo host.")
    serve_demo.add_argument("--bind", default="127.0.0.1")
    serve_demo.add_argument("--port", type=int, default=8765)
    serve_demo.add_argument("--store", default=".chp/demo-http-host.sqlite")
    serve_demo.set_defaults(func=cmd_serve_demo)

    invoke = subcommands.add_parser("invoke", help="Invoke a capability on a served host.")
    invoke.add_argument("capability_id")
    invoke.add_argument("--url", default="http://127.0.0.1:8765")
    invoke.add_argument("--payload", default="{}")
    invoke.add_argument("--correlation-id")
    invoke.add_argument("--subject", default='{"id":"cli","type":"user"}')
    invoke.set_defaults(func=cmd_invoke)

    replay = subcommands.add_parser("replay", help="Replay evidence by correlation ID.")
    replay.add_argument("correlation_id")
    replay.add_argument("--url", default="http://127.0.0.1:8765")
    replay.add_argument("--no-payloads", action="store_true")
    replay.set_defaults(func=cmd_replay)

    demo = subcommands.add_parser("demo", help="Run a local demo.")
    demo_subcommands = demo.add_subparsers(dest="demo_command", required=True)
    endpoint = demo_subcommands.add_parser("endpoint", help="Run the endpoint demo.")
    endpoint.set_defaults(func=cmd_demo_endpoint)

    work = subcommands.add_parser("work", help="Record and inspect CHP development work.")
    work_subcommands = work.add_subparsers(dest="work_command", required=True)

    record = work_subcommands.add_parser("record", help="Record an engineering action.")
    add_work_record_args(record)
    record.set_defaults(func=cmd_work_record)

    run = work_subcommands.add_parser("run", help="Run a command and record the result.")
    add_work_record_args(run)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_work_run)

    work_replay = work_subcommands.add_parser("replay", help="Replay work evidence.")
    work_replay.add_argument("correlation_id")
    work_replay.add_argument("--store", default=DEFAULT_WORK_STORE)
    work_replay.set_defaults(func=cmd_work_replay)

    explain = work_subcommands.add_parser("explain", help="Explain work evidence.")
    explain.add_argument("correlation_id")
    explain.add_argument("--store", default=DEFAULT_WORK_STORE)
    explain.set_defaults(func=cmd_work_explain)

    summary = work_subcommands.add_parser("summary", help="Summarize work evidence.")
    summary.add_argument("correlation_id")
    summary.add_argument("--store", default=DEFAULT_WORK_STORE)
    summary.set_defaults(func=cmd_work_summary)

    validate = work_subcommands.add_parser("validate-demo", help="Validate a demo through CHP evidence.")
    validate.add_argument("demo", choices=["endpoint"])
    validate.add_argument("--correlation-id", default="chp-validate-demo")
    validate.add_argument("--store", default=DEFAULT_WORK_STORE)
    validate.set_defaults(func=cmd_work_validate_demo)

    alignment = work_subcommands.add_parser("check-alignment", help="Check spec/schema/model/type alignment.")
    alignment.add_argument("--correlation-id", default="chp-check-alignment")
    alignment.add_argument("--store", default=DEFAULT_WORK_STORE)
    alignment.add_argument("--repo-root", default=".")
    alignment.set_defaults(func=cmd_work_check_alignment)

    messaging = work_subcommands.add_parser("check-messaging", help="Check public launch messaging.")
    messaging.add_argument("--correlation-id", default="chp-check-messaging")
    messaging.add_argument("--store", default=DEFAULT_WORK_STORE)
    messaging.add_argument("--repo-root", default=".")
    messaging.set_defaults(func=cmd_work_check_messaging)

    inventory = work_subcommands.add_parser("inventory", help="List CHP capabilities for agentic development.")
    inventory.add_argument("--correlation-id", default="chp-agentic-capability-inventory")
    inventory.add_argument("--store", default=DEFAULT_WORK_STORE)
    inventory.add_argument("--implemented-only", action="store_true")
    inventory.set_defaults(func=cmd_work_inventory)

    audit = work_subcommands.add_parser("audit-evidence", help="Audit a trace for evidence quality.")
    audit.add_argument("target_correlation_id")
    audit.add_argument("--correlation-id", default="chp-audit-evidence-quality")
    audit.add_argument("--store", default=DEFAULT_WORK_STORE)
    audit.set_defaults(func=cmd_work_audit_evidence)

    conformance = work_subcommands.add_parser("conformance-matrix", help="Run the local CHP conformance matrix.")
    conformance.add_argument("--correlation-id", default="chp-conformance-matrix")
    conformance.add_argument("--store", default=DEFAULT_WORK_STORE)
    conformance.add_argument("--repo-root", default=".")
    conformance.add_argument("--target", action="append", default=[])
    conformance.add_argument("--timeout-seconds", type=int, default=120)
    conformance.set_defaults(func=cmd_work_conformance_matrix)

    validate_contract = subcommands.add_parser(
        "validate-contract",
        help="Validate a capability descriptor JSON file against the CHP schema.",
    )
    validate_contract.add_argument("descriptor", help="Path to capability-descriptor JSON file.")
    validate_contract.add_argument(
        "--schema",
        default=None,
        help="Path to the schema file (default: auto-located from schemas/).",
    )
    validate_contract.set_defaults(func=cmd_validate_contract)

    vc = work_subcommands.add_parser("vc", help="Govern local version-control work through CHP.")
    vc_subcommands = vc.add_subparsers(dest="vc_command", required=True)

    vc_inspect = vc_subcommands.add_parser("inspect", help="Inspect the local Git repository.")
    add_vc_common_args(vc_inspect, "chp-vc-inspect")
    vc_inspect.set_defaults(func=cmd_work_vc_inspect)

    vc_diff = vc_subcommands.add_parser("diff", help="Summarize local Git changes.")
    add_vc_common_args(vc_diff, "chp-vc-diff")
    vc_diff.add_argument("--include-patch", action="store_true")
    vc_diff.set_defaults(func=cmd_work_vc_diff)

    vc_precommit = vc_subcommands.add_parser("precommit", help="Run checks and record pre-commit evidence.")
    add_vc_common_args(vc_precommit, "chp-vc-precommit")
    vc_precommit.add_argument("--check", action="append", default=[])
    vc_precommit.add_argument("--timeout-seconds", type=int, default=120)
    vc_precommit.set_defaults(func=cmd_work_vc_precommit)

    vc_bundle = vc_subcommands.add_parser("release-bundle", help="Generate a version-control release evidence bundle.")
    add_vc_common_args(vc_bundle, "chp-vc-release-bundle")
    vc_bundle.add_argument("--check", action="append", default=[])
    vc_bundle.add_argument("--include-correlation", action="append", default=[])
    vc_bundle.set_defaults(func=cmd_work_vc_release_bundle)

    vc_readiness = vc_subcommands.add_parser("merge-readiness", help="Verify local merge readiness.")
    add_vc_common_args(vc_readiness, "chp-vc-merge-readiness")
    vc_readiness.add_argument("--check", action="append", default=[])
    vc_readiness.add_argument("--include-correlation", action="append", default=[])
    vc_readiness.add_argument("--release-correlation-id")
    vc_readiness.add_argument("--patch-id")
    vc_readiness.add_argument("--require-approval", action="store_true")
    vc_readiness.add_argument("--approval", action="store_true")
    vc_readiness.add_argument("--allow-dirty", action="store_true")
    vc_readiness.add_argument("--timeout-seconds", type=int, default=120)
    vc_readiness.set_defaults(func=cmd_work_vc_merge_readiness)

    # --- hook group (called from Claude Code hooks, must exit 0) ---
    hook_p = subcommands.add_parser("hook", help="Process a Claude Code hook event from stdin.")
    hook_sub = hook_p.add_subparsers(dest="hook_command", required=True)

    pre_tool_p = hook_sub.add_parser("pre-tool", help="Process a PreToolUse hook event.")
    pre_tool_p.add_argument("--store", default=None, help="Evidence store path.")
    pre_tool_p.add_argument("--policy", default=None, help="Policy file path (default: auto-locate).")
    pre_tool_p.set_defaults(func=cmd_hook_pre_tool)

    post_tool_p = hook_sub.add_parser("post-tool", help="Process a PostToolUse hook event.")
    post_tool_p.add_argument("--store", default=None, help="Evidence store path.")
    post_tool_p.set_defaults(func=cmd_hook_post_tool)

    stop_p = hook_sub.add_parser("stop", help="Process a Stop hook event.")
    stop_p.add_argument("--store", default=None, help="Evidence store path.")
    stop_p.set_defaults(func=cmd_hook_stop)

    # --- hooks group (user-facing setup) ---
    hooks_p = subcommands.add_parser("hooks", help="Manage Claude Code hook registration.")
    hooks_sub = hooks_p.add_subparsers(dest="hooks_command", required=True)

    hooks_install_p = hooks_sub.add_parser("install", help="Install CHP hooks into Claude Code settings.")
    hooks_install_p.add_argument("--global", dest="global_scope", action="store_true",
                                 help="Install to ~/.claude/settings.json (default).")
    hooks_install_p.add_argument("--project", action="store_true",
                                 help="Install to .claude/settings.json in cwd.")
    hooks_install_p.add_argument("--with-governance", dest="with_governance", action="store_true",
                                 help="Also install the PreToolUse governance hook.")
    hooks_install_p.set_defaults(func=cmd_hooks_install)

    hooks_uninstall_p = hooks_sub.add_parser("uninstall", help="Remove CHP hooks from Claude Code settings.")
    hooks_uninstall_p.add_argument("--global", dest="global_scope", action="store_true")
    hooks_uninstall_p.add_argument("--project", action="store_true")
    hooks_uninstall_p.set_defaults(func=cmd_hooks_uninstall)

    hooks_status_p = hooks_sub.add_parser("status", help="Show whether CHP hooks are installed.")
    hooks_status_p.add_argument("--global", dest="global_scope", action="store_true")
    hooks_status_p.add_argument("--project", action="store_true")
    hooks_status_p.set_defaults(func=cmd_hooks_status)

    # --- session group (user-facing replay) ---
    session_p = subcommands.add_parser("session", help="Query and replay Claude Code sessions.")
    session_sub = session_p.add_subparsers(dest="session_command", required=True)

    session_list_p = session_sub.add_parser("list", help="List recent sessions.")
    session_list_p.add_argument("--store", default=None)
    session_list_p.add_argument("--limit", type=int, default=20)
    session_list_p.set_defaults(func=cmd_session_list)

    session_replay_p = session_sub.add_parser("replay", help="Print all evidence for a session.")
    session_replay_p.add_argument("session_id")
    session_replay_p.add_argument("--store", default=None)
    session_replay_p.set_defaults(func=cmd_session_replay)

    session_show_p = session_sub.add_parser("show", help="Show a rich summary of a session.")
    session_show_p.add_argument("session_id")
    session_show_p.add_argument("--store", default=None)
    session_show_p.set_defaults(func=cmd_session_show)

    session_export_p = session_sub.add_parser("export", help="Export a session as a portable JSON bundle.")
    session_export_p.add_argument("session_id")
    session_export_p.add_argument("--store", default=None)
    session_export_p.add_argument("--output", default=None, help="Output file path (default: stdout).")
    session_export_p.set_defaults(func=cmd_session_export)

    return parser


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



def cmd_host(args: argparse.Namespace) -> int:
    print_json(request_json("GET", f"{args.url.rstrip('/')}/host"))
    return 0


def cmd_serve_demo(args: argparse.Namespace) -> int:
    host = build_demo_host(args.store)
    print(f"Serving CHP host {host.host_id} at http://{args.bind}:{args.port}")
    print("Routes: GET /host, GET /capabilities, POST /invoke, POST /replay, GET /replay/{correlation_id}")
    try:
        serve_http(host, bind=args.bind, port=args.port)
    except KeyboardInterrupt:
        print("\nStopped CHP demo host.")
    return 0


def cmd_invoke(args: argparse.Namespace) -> int:
    body: JSON = {
        "capability_id": args.capability_id,
        "payload": parse_json_object(args.payload, "--payload"),
        "subject": parse_json_object(args.subject, "--subject"),
    }
    if args.correlation_id:
        body["correlation_id"] = args.correlation_id
    print_json(request_json("POST", f"{args.url.rstrip('/')}/invoke", body))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    body = {
        "correlation_id": args.correlation_id,
        "include_payloads": not args.no_payloads,
    }
    print_json(request_json("POST", f"{args.url.rstrip('/')}/replay", body))
    return 0


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


def _resolve_store(store: str | None) -> str:
    if store is not None:
        return store
    from .hooks import default_store_path
    return default_store_path()


def _settings_path(global_scope: bool, project: bool) -> str:
    from pathlib import Path
    if project:
        return str(Path(".claude") / "settings.json")
    return str(Path.home() / ".claude" / "settings.json")


def _install_hooks(settings_path: str, with_governance: bool = False) -> None:
    """Add CHP hooks to a Claude Code settings.json file (idempotent)."""
    from pathlib import Path

    path = Path(settings_path)
    settings: dict = {}
    if path.exists():
        with path.open() as f:
            settings = json.load(f)

    hooks = settings.setdefault("hooks", {})

    def _existing_commands(event: str) -> list[str]:
        return [
            h["command"]
            for entry in hooks.get(event, [])
            for h in entry.get("hooks", [])
            if h.get("type") == "command"
        ]

    if with_governance and "chp hook pre-tool" not in _existing_commands("PreToolUse"):
        hooks.setdefault("PreToolUse", []).append({
            "matcher": "",
            "hooks": [{"type": "command", "command": "chp hook pre-tool", "timeout": 5}],
        })

    if "chp hook post-tool" not in _existing_commands("PostToolUse"):
        hooks.setdefault("PostToolUse", []).append({
            "matcher": "",
            "hooks": [{"type": "command", "command": "chp hook post-tool", "timeout": 5}],
        })

    if "chp hook stop" not in _existing_commands("Stop"):
        hooks.setdefault("Stop", []).append({
            "hooks": [{"type": "command", "command": "chp hook stop", "timeout": 5}],
        })

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(settings, f, indent=2)


def _uninstall_hooks(settings_path: str) -> None:
    """Remove CHP hooks from a Claude Code settings.json file."""
    from pathlib import Path

    path = Path(settings_path)
    if not path.exists():
        return

    with path.open() as f:
        settings = json.load(f)

    hooks = settings.get("hooks", {})
    chp_commands = {"chp hook pre-tool", "chp hook post-tool", "chp hook stop"}

    for event in ("PreToolUse", "PostToolUse", "Stop"):
        entries = hooks.get(event, [])
        cleaned = []
        for entry in entries:
            remaining = [h for h in entry.get("hooks", []) if h.get("command") not in chp_commands]
            if remaining:
                cleaned.append({**entry, "hooks": remaining})
        if cleaned:
            hooks[event] = cleaned
        elif event in hooks:
            del hooks[event]

    with path.open("w") as f:
        json.dump(settings, f, indent=2)


def cmd_hook_pre_tool(args: argparse.Namespace) -> int:
    import sys
    from .hooks import default_store_path, process_pre_tool_use
    from .policy import load_policy

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        policy = load_policy(getattr(args, "policy", None))
        result = process_pre_tool_use(payload, store_path, policy=policy)
        if result.should_block:
            print(f"CHP: blocked — {result.reason}", file=sys.stderr)
            return 2
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_post_tool(args: argparse.Namespace) -> int:
    import sys
    from .hooks import default_store_path, process_post_tool_use

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_post_tool_use(payload, store_path)
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_stop(args: argparse.Namespace) -> int:
    import sys
    from .hooks import default_store_path, process_stop

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_stop(payload, store_path)
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hooks_install(args: argparse.Namespace) -> int:
    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    _install_hooks(path, with_governance=getattr(args, "with_governance", False))
    print(f"CHP hooks installed in {path}")
    return 0


def cmd_hooks_uninstall(args: argparse.Namespace) -> int:
    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    _uninstall_hooks(path)
    print(f"CHP hooks removed from {path}")
    return 0


def cmd_hooks_status(args: argparse.Namespace) -> int:
    from pathlib import Path

    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    p = Path(path)
    if not p.exists():
        print(f"Settings not found: {path}")
        return 0

    with p.open() as f:
        settings = json.load(f)

    hooks = settings.get("hooks", {})

    def _has_command(event: str, cmd: str) -> bool:
        return cmd in [
            h["command"]
            for entry in hooks.get(event, [])
            for h in entry.get("hooks", [])
            if h.get("type") == "command"
        ]

    print(f"Settings: {path}")
    print(f"  PreToolUse hook:  {'installed' if _has_command('PreToolUse', 'chp hook pre-tool') else 'not installed'}")
    print(f"  PostToolUse hook: {'installed' if _has_command('PostToolUse', 'chp hook post-tool') else 'not installed'}")
    print(f"  Stop hook:        {'installed' if _has_command('Stop', 'chp hook stop') else 'not installed'}")
    return 0


def cmd_session_list(args: argparse.Namespace) -> int:
    from .store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.query(capability_id="claude_code.session", limit=args.limit)
    finally:
        store.close()

    if not events:
        print("No sessions found.")
        return 0

    print_json(events)
    return 0


def cmd_session_replay(args: argparse.Namespace) -> int:
    from .store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}")
        return 1

    print_json(events)
    return 0


_FILE_TOOLS = {
    "claude_code.read", "claude_code.edit", "claude_code.write",
    "claude_code.grep", "claude_code.glob",
}


def cmd_session_show(args: argparse.Namespace) -> int:
    from collections import Counter

    from .store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}")
        return 1

    tool_events = [e for e in events if e.get("event_type") == "tool_use"]
    requested_events = [e for e in events if e.get("event_type") == "tool_use_requested"]
    session_ev = next((e for e in events if e.get("event_type") == "session_completed"), None)
    failures = [e for e in tool_events if e.get("outcome") == "failure"]

    files_touched: set[str] = set()
    commands_run: list[dict[str, Any]] = []
    for event in tool_events:
        cap_id = event.get("capability_id", "")
        inp = event.get("payload", {}).get("tool_input", {}) or {}
        if cap_id in _FILE_TOOLS:
            for key in ("file_path", "path", "pattern"):
                if val := inp.get(key):
                    files_touched.add(val)
        if cap_id == "claude_code.bash":
            commands_run.append({
                "command": (inp.get("command") or "")[:120],
                "outcome": event.get("outcome"),
            })

    timestamps = [e.get("timestamp") for e in events if e.get("timestamp")]
    duration_seconds: float | None = None
    if len(timestamps) >= 2:
        try:
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S"
            t0 = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
            duration_seconds = round((t1 - t0).total_seconds(), 1)
        except Exception:  # noqa: BLE001
            pass

    tool_counts: Counter[str] = Counter(e.get("capability_id") for e in tool_events)
    summary: JSON = {
        "session_id": args.session_id,
        "tool_count": len(tool_events),
        "requested_count": len(requested_events),
        "failure_count": len(failures),
        "duration_seconds": duration_seconds,
        "tools_used": dict(tool_counts.most_common()),
        "files_touched": sorted(files_touched),
        "commands_run": commands_run,
        "failures": [
            {"capability_id": e.get("capability_id"), "timestamp": e.get("timestamp")}
            for e in failures
        ],
    }
    if session_ev:
        summary["transcript_path"] = session_ev.get("payload", {}).get("transcript_path", "")

    print_json(summary)
    return 0


def cmd_session_export(args: argparse.Namespace) -> int:
    import sys
    from .store import SQLiteEvidenceStore
    from .types import utc_now

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.session_id)
    finally:
        store.close()

    if not events:
        print(f"No events found for session: {args.session_id}", file=sys.stderr)
        return 1

    bundle = {
        "format": "chp-session-bundle/1",
        "session_id": args.session_id,
        "exported_at": utc_now(),
        "event_count": len(events),
        "events": events,
    }

    output = json.dumps(bundle, indent=2, sort_keys=True)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(output)
        print(f"Exported {len(events)} events to {args.output}")
    else:
        print(output)
    return 0


def cmd_validate_contract(args: argparse.Namespace) -> int:
    import sys
    from pathlib import Path

    descriptor_path = Path(args.descriptor)
    if not descriptor_path.exists():
        print(f"Error: file not found: {descriptor_path}", file=sys.stderr)
        return 1

    try:
        with descriptor_path.open() as f:
            descriptor = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {descriptor_path}: {exc}", file=sys.stderr)
        return 1

    if args.schema:
        schema_path = Path(args.schema)
    else:
        # Locate schema relative to this module
        schema_path = Path(__file__).resolve().parent.parent.parent.parent / "schemas" / "capability-descriptor.schema.json"
        if not schema_path.exists():
            # Try next to the installed package
            schema_path = Path(__file__).resolve().parent.parent.parent.parent.parent / "schemas" / "capability-descriptor.schema.json"

    if not schema_path.exists():
        print(
            f"Error: schema not found at {schema_path}. Pass --schema <path> to specify.",
            file=sys.stderr,
        )
        return 1

    try:
        import jsonschema
    except ImportError:
        print(
            "Error: jsonschema is required: pip install chp-core[dev]",
            file=sys.stderr,
        )
        return 1

    with schema_path.open() as f:
        schema = json.load(f)

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(descriptor), key=lambda e: list(e.path))

    if not errors:
        print(f"PASS  {descriptor_path}")
        return 0

    print(f"FAIL  {descriptor_path}  ({len(errors)} error(s))")
    for err in errors:
        path = " > ".join(str(p) for p in err.absolute_path) or "(root)"
        print(f"  [{path}]  {err.message}")
    return 1


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


def cmd_demo_endpoint(_args: argparse.Namespace) -> int:
    server = create_http_server(build_demo_host(), port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    correlation_id = "demo-http-correlation"

    try:
        host_descriptor = request_json("GET", f"{base_url}/host")
        print_json(
            "Discovered Host",
            {
                "id": host_descriptor["id"],
                "capability_ids": [
                    capability["id"] for capability in host_descriptor["capabilities"]
                ],
            },
        )

        search = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.search_information",
                "payload": {"query": "CHP vs MCP"},
                "correlation_id": correlation_id,
                "subject": {"id": "demo-agent", "type": "agent"},
            },
        )
        print_json("Search Invocation Result", search)

        denied = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.deploy_preview",
                "payload": {"project": "chp"},
                "correlation_id": correlation_id,
                "subject": {"id": "demo-agent", "type": "agent"},
            },
        )
        print_json("Denied Invocation Result", denied)

        explanation = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "explain_execution",
                "payload": {"correlation_id": correlation_id},
                "correlation_id": f"{correlation_id}-explanation",
            },
        )
        print_json(
            "Evidence-Backed Explanation",
            {
                "facts": explanation["data"]["facts"],
                "inferences": explanation["data"]["inferences"],
            },
        )

        counterfactual = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "evaluate_counterfactual",
                "payload": {
                    "correlation_id": correlation_id,
                    "invariant": {
                        "id": "warn_on_search_tool",
                        "kind": "capability_id_matches",
                        "failure_behavior": "warn",
                        "parameters": {"capability_id": "demo.search_information"},
                    },
                },
                "correlation_id": f"{correlation_id}-counterfactual",
            },
        )
        print_json(
            "Counterfactual",
            {
                "would_have_warned": counterfactual["data"]["would_have_warned"],
                "violating_events": counterfactual["data"]["violating_events"],
            },
        )

        replay = request_json("GET", f"{base_url}/replay/{correlation_id}")
        print_json(
            "Replay",
            [
                {
                    "sequence": event["sequence"],
                    "event_type": event["event_type"],
                    "capability_id": event["capability_id"],
                    "outcome": event["outcome"],
                }
                for event in replay["events"]
            ],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return 0


def request_json(method: str, url: str, body: JSON | None = None) -> JSON:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object response")
    return value


def parse_json_object(raw: str, flag: str) -> JSON:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{flag} must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{flag} must be a JSON object")
    return value


def print_json(value: Any, data: Any | None = None) -> None:
    if data is None:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    print(f"\n## {value}")
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
