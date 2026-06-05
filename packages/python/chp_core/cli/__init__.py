"""Command-line interface for the CHP reference host."""

from __future__ import annotations

import argparse

from ..work import DEFAULT_WORK_STORE
from ._core import (
    cmd_demo_endpoint,
    cmd_host,
    cmd_invoke,
    cmd_replay,
    cmd_serve_demo,
    cmd_validate_contract,
    cmd_verify_evidence,
)
from ._hooks import (
    _install_hooks,
    _settings_path,
    _uninstall_hooks,
    cmd_hook_codex_post_tool,
    cmd_hook_codex_stop,
    cmd_hook_gemini_post_tool,
    cmd_hook_gemini_stop,
    cmd_hook_post_tool,
    cmd_hook_pre_tool,
    cmd_hook_stop,
    cmd_hooks_install,
    cmd_hooks_status,
    cmd_hooks_uninstall,
)
from ._registry import (
    cmd_registry_add,
    cmd_registry_list,
    cmd_registry_remove,
    cmd_registry_status,
)
from ._session import (
    cmd_session_export,
    cmd_session_list,
    cmd_session_otel,
    cmd_session_replay,
    cmd_session_show,
    cmd_session_tree,
)
from ._ci import (
    cmd_ci_check,
    cmd_policy_lint,
)
from ._work import (
    add_vc_common_args,
    add_work_record_args,
    cmd_work_audit_evidence,
    cmd_work_check_alignment,
    cmd_work_check_messaging,
    cmd_work_conformance_matrix,
    cmd_work_explain,
    cmd_work_inventory,
    cmd_work_radicle_identity,
    cmd_work_radicle_patch_comment,
    cmd_work_radicle_patch_inspect,
    cmd_work_radicle_patch_merge,
    cmd_work_radicle_patch_merge_dry_run,
    cmd_work_radicle_patches_list,
    cmd_work_radicle_repo_status,
    cmd_work_record,
    cmd_work_replay,
    cmd_work_run,
    cmd_work_summary,
    cmd_work_validate_demo,
    cmd_work_vc_diff,
    cmd_work_vc_inspect,
    cmd_work_vc_merge_readiness,
    cmd_work_vc_precommit,
    cmd_work_vc_release_bundle,
)

__all__ = ["main", "build_parser"]


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

    codex_post_p = hook_sub.add_parser("codex-post-tool", help="Process an OpenAI Codex CLI PostToolUse event.")
    codex_post_p.add_argument("--store", default=None)
    codex_post_p.set_defaults(func=cmd_hook_codex_post_tool)

    codex_stop_p = hook_sub.add_parser("codex-stop", help="Process an OpenAI Codex CLI Stop event.")
    codex_stop_p.add_argument("--store", default=None)
    codex_stop_p.set_defaults(func=cmd_hook_codex_stop)

    gemini_post_p = hook_sub.add_parser("gemini-post-tool", help="Process a Gemini CLI PostToolUse event.")
    gemini_post_p.add_argument("--store", default=None)
    gemini_post_p.set_defaults(func=cmd_hook_gemini_post_tool)

    gemini_stop_p = hook_sub.add_parser("gemini-stop", help="Process a Gemini CLI Stop event.")
    gemini_stop_p.add_argument("--store", default=None)
    gemini_stop_p.set_defaults(func=cmd_hook_gemini_stop)

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

    session_tree_p = session_sub.add_parser("tree", help="Show the multi-agent call tree for a session.")
    session_tree_p.add_argument("session_id")
    session_tree_p.add_argument("--store", default=None)
    session_tree_p.add_argument("--depth", type=int, default=10, help="Max recursion depth.")
    session_tree_p.set_defaults(func=cmd_session_tree)

    session_otel_p = session_sub.add_parser("otel", help="Export a session as OTLP spans.")
    session_otel_p.add_argument("session_id")
    session_otel_p.add_argument("--store", default=None)
    session_otel_p.add_argument("--endpoint", default="http://localhost:4318/v1/traces")
    session_otel_p.add_argument("--dry-run", action="store_true", help="Print spans as JSON instead of exporting.")
    session_otel_p.set_defaults(func=cmd_session_otel)

    session_export_p = session_sub.add_parser("export", help="Export a session as a portable JSON bundle.")
    session_export_p.add_argument("session_id")
    session_export_p.add_argument("--store", default=None)
    session_export_p.add_argument("--output", default=None, help="Output file path (default: stdout).")
    session_export_p.set_defaults(func=cmd_session_export)

    registry_p = subcommands.add_parser("registry", help="Manage the local CHP adapter registry.")
    registry_sub = registry_p.add_subparsers(dest="registry_command", required=True)

    registry_list_p = registry_sub.add_parser("list", help="List registered adapters.")
    registry_list_p.add_argument("--registry", default=None, help="Path to registry.json")
    registry_list_p.set_defaults(func=cmd_registry_list)

    registry_add_p = registry_sub.add_parser("add", help="Add or update an adapter entry.")
    registry_add_p.add_argument("adapter_id")
    registry_add_p.add_argument("--package", default=None)
    registry_add_p.add_argument("--version", default=None)
    registry_add_p.add_argument("--tag", action="append", dest="tags", default=[])
    registry_add_p.add_argument("--disabled", action="store_true")
    registry_add_p.add_argument("--registry", default=None)
    registry_add_p.set_defaults(func=cmd_registry_add)

    registry_remove_p = registry_sub.add_parser("remove", help="Remove an adapter entry.")
    registry_remove_p.add_argument("adapter_id")
    registry_remove_p.add_argument("--registry", default=None)
    registry_remove_p.set_defaults(func=cmd_registry_remove)

    registry_status_p = registry_sub.add_parser("status", help="Show maturity status of registered adapters.")
    registry_status_p.add_argument("--registry", default=None)
    registry_status_p.set_defaults(func=cmd_registry_status)

    verify_p = subcommands.add_parser("verify-evidence", help="Verify the SHA256 hash chain for a session.")
    verify_p.add_argument("session_id")
    verify_p.add_argument("--store", default=None)
    verify_p.set_defaults(func=cmd_verify_evidence)

    # --- policy group ---
    policy_p = subcommands.add_parser("policy", help="Validate and lint CHP policy files.")
    policy_sub = policy_p.add_subparsers(dest="policy_command", required=True)

    policy_lint_p = policy_sub.add_parser("lint", help="Validate a policy JSON file for correctness.")
    policy_lint_p.add_argument("policy_file", nargs="?", default=None,
                               help="Path to policy JSON (default: auto-locate .chp/policy.json).")
    policy_lint_p.set_defaults(func=cmd_policy_lint)

    # --- ci group ---
    ci_p = subcommands.add_parser("ci", help="CI gate commands for governed agent sessions.")
    ci_sub = ci_p.add_subparsers(dest="ci_command", required=True)

    ci_check_p = ci_sub.add_parser("check", help="Evaluate stored sessions against a policy; exit 1 on violations.")
    ci_check_p.add_argument("--session", default=None, metavar="SESSION_ID",
                            help="Check a single session (default: all recorded sessions).")
    ci_check_p.add_argument("--policy", default=None, metavar="FILE",
                            help="Policy file path (default: auto-locate .chp/policy.json).")
    ci_check_p.add_argument("--store", default=None, metavar="PATH",
                            help="Evidence store path (default: ~/.chp/claude-code-sessions.sqlite).")
    ci_check_p.add_argument("--since", default=None, metavar="ISO_TS",
                            help="Only check sessions recorded after this timestamp.")
    ci_check_p.add_argument("--fail-on-denied", action="store_true",
                            help="Also fail on events that were already denied at recording time.")
    ci_check_p.set_defaults(func=cmd_ci_check)

    return parser


if __name__ == "__main__":
    raise SystemExit(main())
