"""MCP tool schemas and handlers — thin wrappers over chp_inspector modules."""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

# Default evidence store (same as chp_inspector)
_DEFAULT_STORE = str(Path.home() / ".chp" / "claude-code-sessions.sqlite")

# Repo root relative to this file: tools/chp_mcp/tools.py → chp-core/
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Work evidence store (dev decisions, Radicle ops, VC pipeline)
_WORK_STORE = str(_REPO_ROOT / ".chp" / "codex-self-observation.sqlite")


def _capture(fn, *args, **kwargs) -> str:
    """Call fn(*args, **kwargs) and return everything it prints."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue().strip()


def _invoke_work(capability_id: str, payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Invoke a capability through the work host; returns (success, data)."""
    from chp_core.work_host import build_work_host
    result = build_work_host(_WORK_STORE).invoke(capability_id, payload)
    return result.success, result.data or {}


def _format_radicle(data: dict[str, Any]) -> str:
    available = data.get("available", True)
    if not available:
        return f"Radicle CLI not available: {data.get('stderr_preview', 'rad not found')}"
    passed = data.get("passed", False)
    op = data.get("operation", "")
    rc = data.get("returncode", "?")
    preview = data.get("stdout_preview", "")
    lines = [f"{'✓' if passed else '✗'} {op} (exit {rc})"]
    if preview:
        lines.append(preview)
    elif data.get("stderr_preview"):
        lines.append(data["stderr_preview"])
    return "\n".join(lines)


# ── Tool schemas (MCP inputSchema format) ────────────────────────────────────

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "chp_sessions",
        "description": (
            "List recent CHP sessions recorded from Claude Code. "
            "Returns a table of session IDs, tool counts, and timestamps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max sessions to return (default: 20)"},
            },
        },
    },
    {
        "name": "chp_show",
        "description": (
            "Show a detailed summary of a single CHP session: duration, tool calls, "
            "files read/written, shell commands, failures, and chain integrity status."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "The session ID to inspect"},
            },
        },
    },
    {
        "name": "chp_tree",
        "description": (
            "Show the multi-agent session tree rooted at a session ID. "
            "Displays parent→child relationships and hash-chain integrity at every node."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "Root session ID"},
                "depth": {"type": "integer", "description": "Max tree depth (default: 10)"},
            },
        },
    },
    {
        "name": "chp_query",
        "description": (
            "Query the raw evidence store with optional filters. "
            "Returns a table of matching events: seq, type, capability, outcome, timestamp."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability_id": {"type": "string", "description": "Filter by capability ID"},
                "outcome": {"type": "string", "description": "Filter by outcome (success/failure/denied)"},
                "since": {"type": "string", "description": "ISO timestamp lower bound"},
                "limit": {"type": "integer", "description": "Max events to return"},
            },
        },
    },
    {
        "name": "chp_breakdown",
        "description": (
            "Show a per-capability breakdown of success/failure/denied counts "
            "across all recorded events. Useful for spotting problematic capabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO timestamp lower bound"},
            },
        },
    },
    {
        "name": "chp_verify",
        "description": (
            "Verify the SHA-256 hash chain for a session. "
            "Reports whether the evidence has been tampered with."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string", "description": "The session ID to verify"},
            },
        },
    },
    {
        "name": "chp_work_alignment",
        "description": (
            "Run the 41 CHP spec/schema/type alignment checks against the repo. "
            "Verifies that spec, JSON schemas, Python types, and TypeScript types are all in sync. "
            "Use at session start and after editing types.py, spec/, or schemas/."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "chp_conformance",
        "description": (
            "Run the 9 CHP v0.1 protocol conformance checks. "
            "Validates capability declaration, invocation, evidence emission, chain replay, "
            "and pre-tool governance. Returns pass/fail for each check."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── Work store query ──────────────────────────────────────────────────────
    {
        "name": "chp_work_status",
        "description": (
            "Query the work evidence store (.chp/codex-self-observation.sqlite) for recent work events. "
            "Shows what dev-workflow capabilities have been invoked (alignment checks, conformance runs, "
            "Radicle operations, VC pipeline steps). Use after work commands to confirm evidence was recorded."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max events to return (default: 20)"},
                "capability_id": {"type": "string", "description": "Filter by capability ID prefix"},
            },
        },
    },
    # ── VC pipeline tools ─────────────────────────────────────────────────────
    {
        "name": "chp_vc_diff",
        "description": (
            "Summarize the current Git working-tree diff and record evidence. "
            "Returns changed files, additions/deletions, and optional patch content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_patch": {"type": "boolean", "description": "Include full diff patch (default: false)"},
            },
        },
    },
    {
        "name": "chp_vc_release_bundle",
        "description": (
            "Generate a release evidence bundle: repo state, diff summary, pre-commit checks, "
            "and referenced work traces. Use before pushing a Radicle patch. "
            "Returns passed:true when all bundle checks pass."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Shell commands to run as pre-commit checks (e.g. ['pytest tests/ -q'])",
                },
                "work_correlation_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Correlation IDs of prior work actions to bundle as evidence",
                },
                "correlation_id": {"type": "string", "description": "ID for this bundle event (default: chp-vc-release-bundle)"},
            },
        },
    },
    {
        "name": "chp_vc_merge_readiness",
        "description": (
            "Verify merge readiness: repo clean, work evidence present, release bundle present, approval. "
            "Returns ready:true/false plus list of failed checks. Final gate before patch merge."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "patch_id": {"type": "string", "description": "Radicle patch ID being merged"},
                "release_correlation_id": {"type": "string", "description": "Correlation ID of the release bundle"},
                "work_correlation_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Correlation IDs of work actions to verify",
                },
                "require_approval": {"type": "boolean", "description": "Fail if no approval recorded"},
                "approval": {"type": "boolean", "description": "Record approval inline"},
                "allow_dirty": {"type": "boolean", "description": "Do not require clean worktree"},
                "correlation_id": {"type": "string", "description": "ID for this check event"},
            },
        },
    },
    # ── Release pipeline tools ────────────────────────────────────────────────
    {
        "name": "chp_version_bump",
        "description": (
            "Validate that pyproject.toml and package.json versions match, "
            "then write the new version to both files. Records evidence."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["new_version"],
            "properties": {
                "new_version": {"type": "string", "description": "New semver string (e.g. 0.3.0)"},
            },
        },
    },
    {
        "name": "chp_rc_tag",
        "description": (
            "Create and push the next RC git tag (v{version}-rc.{n}) to origin. "
            "Triggers CI + TestPyPI staging pipeline. Requires allow_mutation=true."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["version", "allow_mutation"],
            "properties": {
                "version": {"type": "string", "description": "Version string (e.g. 0.3.0)"},
                "allow_mutation": {"type": "boolean", "description": "Must be true to push tag"},
            },
        },
    },
    {
        "name": "chp_release_tag",
        "description": (
            "Create and push the release git tag (v{version}) to origin. "
            "Triggers PyPI + npm production publish via CI. "
            "Requires allow_mutation=true and release_bundle_correlation_id."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["version", "allow_mutation"],
            "properties": {
                "version": {"type": "string", "description": "Version string (e.g. 0.3.0)"},
                "release_bundle_correlation_id": {
                    "type": "string",
                    "description": "Correlation ID of the prior release bundle evidence",
                },
                "allow_mutation": {"type": "boolean", "description": "Must be true to push tag"},
            },
        },
    },
    # ── Radicle patch tools ───────────────────────────────────────────────────
    {
        "name": "chp_radicle_status",
        "description": "Inspect Radicle repository status: RID, sync state, upstream. Records evidence.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "chp_radicle_patches",
        "description": "List Radicle patches (default: open). Records evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["open", "draft", "merged", "archived", "all"],
                    "description": "Filter by patch state (default: open)",
                },
            },
        },
    },
    {
        "name": "chp_radicle_patch_inspect",
        "description": "Inspect a Radicle patch in detail. Records evidence.",
        "inputSchema": {
            "type": "object",
            "required": ["patch_id"],
            "properties": {
                "patch_id": {"type": "string", "description": "Radicle patch ID"},
            },
        },
    },
    {
        "name": "chp_radicle_patch_merge_dry_run",
        "description": "Dry-run a Radicle patch merge to check for conflicts. Records evidence.",
        "inputSchema": {
            "type": "object",
            "required": ["patch_id"],
            "properties": {
                "patch_id": {"type": "string", "description": "Radicle patch ID"},
                "revision": {"type": "string", "description": "Specific revision to test"},
            },
        },
    },
    {
        "name": "chp_radicle_patch_merge",
        "description": (
            "Merge a Radicle patch with governed evidence capture. "
            "Requires allow_mutation=true. Run chp_radicle_patch_merge_dry_run and "
            "chp_vc_merge_readiness first."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["patch_id", "allow_mutation"],
            "properties": {
                "patch_id": {"type": "string", "description": "Radicle patch ID"},
                "revision": {"type": "string", "description": "Specific revision to merge"},
                "allow_mutation": {"type": "boolean", "description": "Must be true to proceed"},
            },
        },
    },
    # ── Radicle issue tools ───────────────────────────────────────────────────
    {
        "name": "chp_radicle_issues",
        "description": "List Radicle issues (default: open). Records evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "all"],
                    "description": "Filter by issue state (default: open)",
                },
            },
        },
    },
    {
        "name": "chp_radicle_issue_inspect",
        "description": "Inspect a Radicle issue in detail. Records evidence.",
        "inputSchema": {
            "type": "object",
            "required": ["issue_id"],
            "properties": {
                "issue_id": {"type": "string", "description": "Radicle issue ID"},
            },
        },
    },
    {
        "name": "chp_radicle_issue_open",
        "description": (
            "Open a new Radicle issue. Records evidence. "
            "Requires allow_mutation=true. Use at the start of a work session to track the task."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["title", "allow_mutation"],
            "properties": {
                "title": {"type": "string", "description": "Issue title"},
                "description": {"type": "string", "description": "Issue description (redacted in evidence)"},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels to apply",
                },
                "allow_mutation": {"type": "boolean", "description": "Must be true to proceed"},
            },
        },
    },
    {
        "name": "chp_radicle_issue_comment",
        "description": (
            "Comment on a Radicle issue. Records evidence. "
            "Requires allow_mutation=true. Use to post status updates or close summaries."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["issue_id", "message", "allow_mutation"],
            "properties": {
                "issue_id": {"type": "string", "description": "Radicle issue ID"},
                "message": {"type": "string", "description": "Comment body (redacted in evidence)"},
                "allow_mutation": {"type": "boolean", "description": "Must be true to proceed"},
            },
        },
    },
]


# ── Tool handlers ─────────────────────────────────────────────────────────────

def dispatch(tool_name: str, arguments: dict[str, Any], store_path: str) -> str:
    """Invoke the named tool and return its text output."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "python"))
    from tools.chp_inspector import (  # noqa: PLC0415  (nested import)
        query_view,
        session_view,
        tree_view,
    )

    if tool_name == "chp_sessions":
        limit = int(arguments.get("limit", 20))
        return _capture(session_view.list_sessions, store_path, limit=limit) or "No sessions found."

    if tool_name == "chp_show":
        return _capture(session_view.show_session, arguments["session_id"], store_path) or "No events found."

    if tool_name == "chp_tree":
        depth = int(arguments.get("depth", 10))
        return _capture(tree_view.render_tree, arguments["session_id"], store_path, depth=depth)

    if tool_name == "chp_query":
        return _capture(
            query_view.run_query,
            store_path,
            capability_id=arguments.get("capability_id"),
            outcome=arguments.get("outcome"),
            since=arguments.get("since"),
            limit=arguments.get("limit"),
        ) or "No events matched."

    if tool_name == "chp_breakdown":
        return _capture(query_view.capability_breakdown, store_path, since=arguments.get("since"))

    if tool_name == "chp_verify":
        buf = io.StringIO()
        with redirect_stdout(buf):
            session_view.verify_session(arguments["session_id"], store_path)
        return buf.getvalue().strip()

    if tool_name == "chp_work_alignment":
        from chp_core.protocol_checks import check_alignment
        result = check_alignment(_REPO_ROOT)
        checks = result.get("checks", [])
        passed = sum(1 for c in checks if c.get("passed"))
        total = len(checks)
        failed = [c for c in checks if not c.get("passed")]
        lines = [f"Alignment: {passed}/{total} checks passed"]
        if failed:
            lines.append("\nFailed checks:")
            for c in failed:
                lines.append(f"  ✗ {c['name']}: {c.get('details', '')}")
        else:
            lines.append("All checks passed — spec, schemas, Python types, and TypeScript are in sync.")
        return "\n".join(lines)

    if tool_name == "chp_conformance":
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(_REPO_ROOT / "conformance" / "runner.py")],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            env={**__import__("os").environ, "PYTHONPATH": str(_REPO_ROOT / "packages" / "python")},
        )
        output = (proc.stdout + proc.stderr).strip()
        return output or ("All conformance checks passed." if proc.returncode == 0 else "Conformance runner failed (no output).")

    # ── Work store query ──────────────────────────────────────────────────────

    if tool_name == "chp_work_status":
        from chp_core.store import SQLiteEvidenceStore
        import os
        from collections import defaultdict
        if not os.path.exists(_WORK_STORE):
            return "Work store not found — no work events recorded yet."
        store = SQLiteEvidenceStore(_WORK_STORE)
        cap_filter = arguments.get("capability_id")
        raw = bool(arguments.get("raw", False))
        events = store.query(capability_id=cap_filter)
        if not events:
            return "No work events found."
        if raw:
            limit = int(arguments.get("limit", 20))
            lines = [f"{'seq':>6}  {'capability_id':<45}  {'outcome':<10}  timestamp"]
            lines.append("-" * 90)
            for ev in events[-limit:]:
                seq = ev.get("sequence", "?")
                cap = ev.get("capability_id") or ev.get("event_type") or "?"
                outcome = ev.get("outcome") or "-"
                ts = (ev.get("timestamp") or "")[:19]
                lines.append(f"{seq:>6}  {cap:<45}  {outcome:<10}  {ts}")
            return "\n".join(lines)
        # Grouped view: group by correlation_id
        groups: dict[str, dict] = defaultdict(lambda: {"events": 0, "caps": set(), "last_ts": "", "outcomes": set()})
        for ev in events:
            cid = (ev.get("correlation") or {}).get("correlation_id") or "unknown"
            cap = ev.get("capability_id") or ""
            ts = (ev.get("timestamp") or "")[:19]
            outcome = ev.get("outcome") or ""
            groups[cid]["events"] += 1
            if cap:
                groups[cid]["caps"].add(cap.split(".")[-1])  # last segment for brevity
            if ts > groups[cid]["last_ts"]:
                groups[cid]["last_ts"] = ts
            if outcome:
                groups[cid]["outcomes"].add(outcome)
        lines = [f"{'correlation_id':<40}  {'ev':>4}  {'outcomes':<18}  {'capabilities':<35}  last_event"]
        lines.append("-" * 120)
        for cid, g in sorted(groups.items(), key=lambda x: x[1]["last_ts"], reverse=True):
            caps = ", ".join(sorted(g["caps"]))[:33]
            outcomes = ", ".join(sorted(g["outcomes"]))[:16]
            lines.append(f"{cid:<40}  {g['events']:>4}  {outcomes:<18}  {caps:<35}  {g['last_ts']}")
        return "\n".join(lines)

    # ── VC pipeline tools ─────────────────────────────────────────────────────

    if tool_name == "chp_vc_diff":
        success, data = _invoke_work("chp.version_control.diff_summary", {
            "repo_root": str(_REPO_ROOT),
            "include_patch": bool(arguments.get("include_patch", False)),
        })
        if not success:
            return f"diff failed: {data.get('error') or data}"
        changed = data.get("changed_files", [])
        summary = data.get("summary") or data.get("stats") or {}
        lines = [f"Changed files ({len(changed)}):"]
        for f in changed[:30]:
            lines.append(f"  {f}")
        if len(changed) > 30:
            lines.append(f"  … and {len(changed) - 30} more")
        if summary:
            lines.append(str(summary))
        if arguments.get("include_patch"):
            patch = data.get("patch") or data.get("diff") or ""
            if patch:
                lines.append("\n" + patch[:4000])
        return "\n".join(lines) or "No changes."

    if tool_name == "chp_vc_release_bundle":
        payload: dict[str, Any] = {"repo_root": str(_REPO_ROOT)}
        if arguments.get("checks"):
            payload["checks"] = arguments["checks"]
        if arguments.get("work_correlation_ids"):
            payload["work_correlation_ids"] = arguments["work_correlation_ids"]
        success, data = _invoke_work("chp.version_control.release_evidence_bundle", payload)
        passed_flag = data.get("passed", False)
        checks = data.get("checks", [])
        lines = [f"Release bundle: {'PASS' if passed_flag else 'FAIL'}"]
        for c in checks:
            mark = "✓" if c.get("passed") else "✗"
            lines.append(f"  {mark} {c['name']}")
        if not success:
            lines.append(f"Error: {data.get('error') or data}")
        return "\n".join(lines)

    if tool_name == "chp_vc_merge_readiness":
        payload = {"repo_root": str(_REPO_ROOT)}
        if arguments.get("patch_id"):
            payload["patch_id"] = arguments["patch_id"]
        if arguments.get("release_correlation_id"):
            payload["release_correlation_id"] = arguments["release_correlation_id"]
        if arguments.get("work_correlation_ids"):
            payload["work_correlation_ids"] = arguments["work_correlation_ids"]
        if arguments.get("require_approval"):
            payload["require_approval"] = True
        if arguments.get("approval"):
            payload["approval"] = True
        if arguments.get("allow_dirty"):
            payload["require_clean"] = False
        success, data = _invoke_work("chp.version_control.verify_merge_readiness", payload)
        ready = data.get("ready", False)
        decision = data.get("decision", "unknown")
        failed = data.get("failed_checks", [])
        checks = data.get("checks", [])
        lines = [f"Merge readiness: {decision.upper()} ({'ready' if ready else 'NOT ready'})"]
        for c in checks:
            mark = "✓" if c.get("passed") else "✗"
            req = " (required)" if c.get("required") else ""
            lines.append(f"  {mark} {c['name']}{req}")
        if failed:
            lines.append(f"\nFailed: {', '.join(failed)}")
        return "\n".join(lines)

    # ── Radicle common payload ────────────────────────────────────────────────

    def _rad_payload(**extra: Any) -> dict[str, Any]:
        return {"repo_root": str(_REPO_ROOT), "timeout_seconds": 30, **extra}

    # ── Radicle patch tools ───────────────────────────────────────────────────

    if tool_name == "chp_radicle_status":
        success, data = _invoke_work("chp.radicle.repo_status", _rad_payload())
        return _format_radicle(data)

    if tool_name == "chp_radicle_patches":
        state = str(arguments.get("state") or "open")
        success, data = _invoke_work("chp.radicle.patches.list", _rad_payload(state=state))
        return _format_radicle(data)

    if tool_name == "chp_radicle_patch_inspect":
        success, data = _invoke_work("chp.radicle.patches.inspect",
                                     _rad_payload(patch_id=arguments["patch_id"]))
        return _format_radicle(data)

    if tool_name == "chp_radicle_patch_merge_dry_run":
        payload = _rad_payload(patch_id=arguments["patch_id"])
        if arguments.get("revision"):
            payload["revision"] = arguments["revision"]
        success, data = _invoke_work("chp.radicle.patches.merge_dry_run", payload)
        return _format_radicle(data)

    if tool_name == "chp_radicle_patch_merge":
        if arguments.get("allow_mutation") is not True:
            return "Denied: allow_mutation must be true to execute a patch merge."
        payload = _rad_payload(patch_id=arguments["patch_id"], allow_mutation=True)
        if arguments.get("revision"):
            payload["revision"] = arguments["revision"]
        success, data = _invoke_work("chp.radicle.patches.merge", payload)
        return _format_radicle(data)

    # ── Radicle issue tools ───────────────────────────────────────────────────

    if tool_name == "chp_radicle_issues":
        state = str(arguments.get("state") or "open")
        success, data = _invoke_work("chp.radicle.issues.list", _rad_payload(state=state))
        return _format_radicle(data)

    if tool_name == "chp_radicle_issue_inspect":
        success, data = _invoke_work("chp.radicle.issues.inspect",
                                     _rad_payload(issue_id=arguments["issue_id"]))
        return _format_radicle(data)

    if tool_name == "chp_radicle_issue_open":
        if arguments.get("allow_mutation") is not True:
            return "Denied: allow_mutation must be true to open an issue."
        payload = _rad_payload(
            title=arguments["title"],
            allow_mutation=True,
        )
        if arguments.get("description"):
            payload["description"] = arguments["description"]
        if arguments.get("labels"):
            payload["labels"] = arguments["labels"]
        success, data = _invoke_work("chp.radicle.issues.open", payload)
        return _format_radicle(data)

    if tool_name == "chp_radicle_issue_comment":
        if arguments.get("allow_mutation") is not True:
            return "Denied: allow_mutation must be true to comment on an issue."
        success, data = _invoke_work("chp.radicle.issues.comment", _rad_payload(
            issue_id=arguments["issue_id"],
            message=arguments["message"],
            allow_mutation=True,
        ))
        return _format_radicle(data)

    # ── Release pipeline tools ────────────────────────────────────────────────

    if tool_name == "chp_version_bump":
        success, data = _invoke_work("chp.version_control.version_bump", {
            "repo_root": str(_REPO_ROOT),
            "new_version": arguments["new_version"],
        })
        if data.get("passed"):
            old = data.get("old_version", "?")
            new = data.get("new_version", "?")
            files = ", ".join(data.get("files_modified", []))
            return f"✓ Version bumped {old} → {new}\nFiles: {files}"
        return f"✗ Version bump failed: {data.get('error') or data}"

    if tool_name == "chp_rc_tag":
        if arguments.get("allow_mutation") is not True:
            return "Denied: allow_mutation must be true to push an RC tag."
        success, data = _invoke_work("chp.version_control.rc_tag", {
            "repo_root": str(_REPO_ROOT),
            "version": arguments["version"],
            "allow_mutation": True,
        })
        if data.get("passed"):
            return f"✓ RC tag pushed: {data.get('tag')}"
        return f"✗ RC tag failed: {data.get('error') or data}"

    if tool_name == "chp_release_tag":
        if arguments.get("allow_mutation") is not True:
            return "Denied: allow_mutation must be true to push a release tag."
        payload: dict[str, Any] = {
            "repo_root": str(_REPO_ROOT),
            "version": arguments["version"],
            "allow_mutation": True,
        }
        if arguments.get("release_bundle_correlation_id"):
            payload["release_bundle_correlation_id"] = arguments["release_bundle_correlation_id"]
        success, data = _invoke_work("chp.version_control.release_tag", payload)
        if data.get("passed"):
            return f"✓ Release tag pushed: {data.get('tag')} — CI will publish to PyPI + npm"
        return f"✗ Release tag failed: {data.get('error') or data}"

    return f"Unknown tool: {tool_name}"
