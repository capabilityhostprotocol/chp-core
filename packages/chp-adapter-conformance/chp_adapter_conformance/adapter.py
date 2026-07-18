"""ConformanceAdapter — governed capability violation checker."""

from __future__ import annotations

import hashlib as _hashlib
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chp_core import BaseAdapter, capability

from .checker import (
    check_commit_message,
    check_registered_adapter,
    check_source_file,
    score,
)

_SESSION_FILE = Path.home() / ".chp" / "active-session.json"  # global default (back-compat)
_SESSION_DIR = Path.home() / ".chp" / "sessions"  # per-repo/worktree keyed sessions


def _session_file(repo_path: str | None) -> Path:
    """Resolve the session-state file. Keyed by repo path when given (so each git worktree gets its
    own session and concurrent builds never clobber each other), else the global file.

    A repo_path NEVER falls back to the global file. The global file is scoped to no repo, so a
    fallback lets one unkeyed session answer for every repo that has no session of its own — and
    since close_dev_session unlinks the file it resolves, a keyed close leaves that global session
    in place to go on satisfying commit gates everywhere, indefinitely. A missing keyed session must
    read as "no session" — loudly — rather than silently borrowing another repo's authority.
    """
    if not repo_path:
        return _SESSION_FILE
    key = _hashlib.sha1(str(Path(repo_path).resolve()).encode()).hexdigest()[:12]
    return _SESSION_DIR / f"{key}.json"

# Declared evidence-emission contract for this adapter's capabilities (the granular
# events each method emits). Declaring the superset makes the catalog honest vs what's
# observed — see chp.adapters.audit.emission_report.
_EMITS = [
    "source_checked", "adapter_checked", "all_checked", "staged_checked",
    "policy_checked", "dev_session_opened", "dev_session_closed", "violations_reported",
]

# The sole adapter sanctioned to import an HTTP client directly: it IS the
# governed transport. Every other adapter must compose through it
# (ctx.ainvoke("chp.adapters.http.request", ...)).
_HTTP_TRANSPORT_ADAPTER = "chp.adapters.http"

# chp_core and chp_host are below/beside the adapter layer and cannot depend on
# chp-adapter-http without creating a circular dependency.
_CORE_PKG_SEGMENT = "chp_core"
_HOST_PKG_SEGMENT = "chp_host"


def _is_test_file(path: Path) -> bool:
    """Test modules legitimately import httpx (MockTransport) etc.; they are not
    capability code and are exempt from the I/O-isolation rules."""
    return "tests" in path.parts or path.name.startswith("test_")


def _is_core_file(path: Path) -> bool:
    """chp_core and chp_host files are below/beside the adapter layer; they
    cannot compose through chp-adapter-http without creating a circular
    dependency."""
    return _CORE_PKG_SEGMENT in path.parts or _HOST_PKG_SEGMENT in path.parts


def _source_of_handler(handler: Any) -> str | None:
    """Follow closure vars to find the adapter source file (handlers are wrappers in chp-core)."""
    if hasattr(handler, "__closure__") and handler.__closure__:
        for cell in handler.__closure__:
            try:
                cv = cell.cell_contents
                if callable(cv):
                    return inspect.getfile(cv)
            except (ValueError, TypeError):
                pass
    try:
        return inspect.getfile(handler)
    except (TypeError, OSError):
        return None


class ConformanceAdapter(BaseAdapter):
    """Static and runtime capability conformance checking."""

    adapter_id = "chp.adapters.conformance"
    adapter_name = "Conformance"
    adapter_description = "Check capability implementations for CHP spec violations (raw I/O, missing schema, issue policy)."
    adapter_category = "core"
    adapter_tags = ["conformance", "linting", "policy", "quality"]

    def __init__(self) -> None:
        self._host: Any = None

    def on_register(self, host: Any) -> None:
        self._host = host

    @capability(
        id="chp.adapters.conformance.check_source",
        emits=_EMITS,
        version="1.0.0",
        description="Run static AST analysis on an adapter source file and report violations.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "source_path": {"type": "string", "description": "Absolute path to a Python adapter source file"},
            },
            "required": ["source_path"],
            "additionalProperties": False,
        },
    )
    async def check_source(self, ctx: Any, payload: dict) -> dict:
        path = Path(payload["source_path"]).expanduser()
        violations = check_source_file(path)
        conformance_score = score(violations)
        ctx.emit("source_checked", {
            "source_path": str(path),
            "violation_count": len(violations),
            "error_count": sum(1 for v in violations if v.severity == "error"),
            "warning_count": sum(1 for v in violations if v.severity == "warning"),
            "score": conformance_score,
        }, redacted=False)
        return {
            "source_path": str(path),
            "violations": [v.to_dict() for v in violations],
            "violation_count": len(violations),
            "score": conformance_score,
        }

    @capability(
        id="chp.adapters.conformance.check_adapter",
        emits=_EMITS,
        version="1.0.0",
        description="Runtime introspection of a loaded adapter — checks schema, version, and metadata completeness.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "adapter_id": {"type": "string", "description": "Adapter ID prefix, e.g. chp.adapters.messages"},
            },
            "required": ["adapter_id"],
            "additionalProperties": False,
        },
    )
    async def check_adapter(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        adapter_id = payload["adapter_id"]

        # Find source files from registered capability handlers
        src_files: set[str] = set()
        for cap_key, reg_cap in self._host._capabilities.items():
            if not cap_key.startswith(adapter_id):
                continue
            src = _source_of_handler(reg_cap.handler)
            if src:
                src_files.add(src)

        if not src_files:
            raise KeyError(f"No capabilities found for adapter_id prefix={adapter_id!r}")

        violations: list = []
        for src in src_files:
            violations.extend(check_source_file(src))

        conformance_score = score(violations)
        ctx.emit("adapter_checked", {
            "adapter_id": adapter_id,
            "violation_count": len(violations),
            "score": conformance_score,
        }, redacted=False)
        return {
            "adapter_id": adapter_id,
            "violations": [v.to_dict() for v in violations],
            "violation_count": len(violations),
            "score": conformance_score,
        }

    @capability(
        id="chp.adapters.conformance.check_all",
        emits=_EMITS,
        version="1.0.0",
        description="Check all loaded adapters for violations and return a ranked summary.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    )
    async def check_all(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        # Group capabilities by their source file (follow closure to original method)
        src_to_prefix: dict[str, str] = {}
        for cap_key, reg_cap in self._host._capabilities.items():
            src = _source_of_handler(reg_cap.handler)
            if src:
                prefix = ".".join(cap_key.split(".")[:3])
                src_to_prefix.setdefault(src, prefix)

        results = []
        for src_file, adapter_id in src_to_prefix.items():
            violations = check_source_file(src_file)
            conformance_score = score(violations)
            results.append({
                "adapter_id": adapter_id,
                "violation_count": len(violations),
                "score": conformance_score,
                "violations": [v.to_dict() for v in violations],
            })

        results.sort(key=lambda r: r["score"])
        total = sum(r["violation_count"] for r in results)
        worst = [r["adapter_id"] for r in results if r["score"] < 80]

        ctx.emit("all_checked", {
            "adapter_count": len(results),
            "total_violations": total,
            "worst_adapters": worst,
        }, redacted=False)
        return {
            "adapters": results,
            "adapter_count": len(results),
            "total_violations": total,
            "worst_adapters": worst,
        }

    @capability(
        id="chp.adapters.conformance.policy_check",
        emits=_EMITS,
        version="1.0.0",
        description="Check a commit message for the Radicle issue reference policy (rad:XXXXXXX).",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "commit_message": {"type": "string"},
            },
            "required": ["commit_message"],
            "additionalProperties": False,
        },
    )
    async def policy_check(self, ctx: Any, payload: dict) -> dict:
        msg = payload["commit_message"]
        violations = check_commit_message(msg)
        passes = len(violations) == 0
        ctx.emit("policy_checked", {
            "passes": passes,
            "violation_count": len(violations),
        }, redacted=False)
        return {
            "passes": passes,
            "violations": [v.to_dict() for v in violations],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_baseline(self, ctx: Any) -> dict:
        """Conformance scan via ctx.ainvoke(check_source) — each check is a governed evidence event."""
        src_to_prefix: dict[str, str] = {}
        for cap_key, reg_cap in self._host._capabilities.items():
            src = _source_of_handler(reg_cap.handler)
            if src:
                prefix = ".".join(cap_key.split(".")[:3])
                src_to_prefix.setdefault(src, prefix)

        results = []
        for src_file, adapter_id in src_to_prefix.items():
            result = await ctx.ainvoke(
                "chp.adapters.conformance.check_source",
                {"source_path": src_file},
            )
            if result.success:
                data = result.data
                results.append({
                    "adapter_id": adapter_id,
                    "violation_count": data["violation_count"],
                    "score": data["score"],
                    "violations": data["violations"],
                })
            else:
                # Fallback: direct call so a broken check_source doesn't block baseline
                violations = check_source_file(src_file)
                conformance_score = score(violations)
                results.append({
                    "adapter_id": adapter_id,
                    "violation_count": len(violations),
                    "score": conformance_score,
                    "violations": [v.to_dict() for v in violations],
                })

        results.sort(key=lambda r: r["score"])
        total = sum(r["violation_count"] for r in results)
        return {"adapters": results, "adapter_count": len(results), "total_violations": total}

    # ------------------------------------------------------------------
    # Dev session management
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.conformance.open_dev_session",
        emits=_EMITS,
        version="1.0.0",
        description="Open a tracked dev session: validate Radicle issue, snapshot baseline conformance, create plan, write active-session state.",
        category="core",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "issue_id": {"type": "string", "description": "Radicle issue short-hash (7+ chars)"},
                "description": {"type": "string", "description": "Optional work description"},
                "repo_path": {"type": "string", "description": "Repo/worktree path to key this session by (defaults to the global session)"},
            },
            "required": ["issue_id"],
            "additionalProperties": False,
        },
    )
    async def open_dev_session(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        issue_id = payload["issue_id"]
        repo_path = payload.get("repo_path")

        # 1. Validate issue exists and is open. Forward repo_path so the issue is
        # resolved against the same repo the session is keyed by — without it,
        # issue_show defaults to the host's cwd and fails for any other repo.
        issue_show_payload = {"issue_id": issue_id}
        if repo_path:
            issue_show_payload["repo_path"] = repo_path
        issue_result = await ctx.ainvoke(
            "chp.adapters.radicle.issue_show",
            issue_show_payload,
        )
        if not issue_result.success:
            raise ValueError(f"Issue {issue_id} not found: {issue_result.error}")
        issue_data = issue_result.data
        issue_title = issue_data.get("title", issue_id)
        issue_state = str(issue_data.get("state", "open"))
        if issue_state not in {"open", ""}:
            raise ValueError(f"Issue {issue_id} is not open (state: {issue_state})")

        # 2. Snapshot baseline conformance (governed — each file check appears in evidence)
        baseline = await self._run_baseline(ctx)

        # 3. Create a planning adapter plan tied to this session
        plan_result = await ctx.ainvoke(
            "chp.adapters.planning.create_plan",
            {
                "intent": f"Resolve rad:{issue_id[:7]} — {issue_title}",
                "steps": [
                    {"step_id": "baseline", "description": "Review violation baseline"},
                    {"step_id": "implement", "description": "Implement fix"},
                    {"step_id": "verify", "description": "Run check_staged — no new violations"},
                    {"step_id": "close", "description": "Close dev session"},
                ],
            },
        )
        plan_id = plan_result.data.get("plan_id") if plan_result.success else None

        # 4. Write session state (sanctioned local state — ~/.chp/ is CHP's own state dir).
        #    Keyed by repo_path when given so worktree builds don't clobber an authoring session.
        session_file = _session_file(payload.get("repo_path"))
        session_file.parent.mkdir(parents=True, exist_ok=True)
        session_data = {
            "issue_id": issue_id,
            "issue_title": issue_title,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "baseline": baseline,
            "plan_id": plan_id,
            "session_correlation_id": ctx.correlation_id,
            "repo_path": payload.get("repo_path"),
        }
        session_file.write_text(json.dumps(session_data, indent=2))

        baseline_total = baseline["total_violations"]
        ctx.emit("dev_session_opened", {
            "issue_id": issue_id,
            "issue_title": issue_title,
            "baseline_total_violations": baseline_total,
            "baseline_adapter_count": baseline["adapter_count"],
            "plan_id": plan_id,
        }, redacted=False)
        return {
            "issue_id": issue_id,
            "issue_title": issue_title,
            "baseline_total_violations": baseline_total,
            "session_file": str(session_file),
            "plan_id": plan_id,
        }

    @capability(
        id="chp.adapters.conformance.check_staged",
        emits=_EMITS,
        version="1.0.0",
        description="Check staged Python files against the active dev session baseline. Returns new violations only — existing baseline violations are not re-flagged.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "staged_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Absolute paths to staged .py files (from git diff --staged --name-only)",
                },
                "repo_path": {"type": "string", "description": "Repo/worktree path keying the session (defaults to global)"},
            },
            "required": ["staged_files"],
            "additionalProperties": False,
        },
    )
    async def check_staged(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        staged_files = payload.get("staged_files", [])

        session_file = _session_file(payload.get("repo_path"))
        if not session_file.exists():
            raise RuntimeError("No active dev session. Run open_dev_session first.")

        session_data = json.loads(session_file.read_text())
        baseline_adapters = session_data.get("baseline", {}).get("adapters", [])

        # Build reverse map: source_file → baseline rule set
        baseline_rules_by_adapter: dict[str, set[str]] = {
            a["adapter_id"]: {v["rule"] for v in a.get("violations", [])}
            for a in baseline_adapters
        }

        # Build map: source_file → adapter_id from currently loaded capabilities,
        # plus directory → adapter_id so sibling isolation modules (_client.py,
        # _backends.py) are attributed to their adapter (closes the blind spot
        # where imported non-capability files were never checked).
        file_to_adapter: dict[str, str] = {}
        dir_to_adapter: dict[str, str] = {}
        for cap_key, reg_cap in self._host._capabilities.items():
            src = _source_of_handler(reg_cap.handler)
            if src:
                adapter_id = ".".join(cap_key.split(".")[:3])
                resolved_src = str(Path(src).resolve())
                file_to_adapter.setdefault(resolved_src, adapter_id)
                dir_to_adapter.setdefault(str(Path(resolved_src).parent), adapter_id)

        new_violations: list[dict] = []
        files_checked: list[str] = []

        for file_path in staged_files:
            path = Path(file_path)
            if not path.exists() or path.suffix != ".py":
                continue
            if _is_test_file(path):
                continue  # tests may use httpx.MockTransport etc.
            if _is_core_file(path):
                continue  # chp_core is below the adapter layer; cannot depend on adapters

            violations = check_source_file(path)
            files_checked.append(str(path))

            resolved = str(path.resolve())
            # Capability file → its adapter; otherwise a sibling module in the
            # same package directory → that adapter.
            adapter_id = file_to_adapter.get(resolved) or dir_to_adapter.get(str(Path(resolved).parent))
            baseline_rules = baseline_rules_by_adapter.get(adapter_id, set()) if adapter_id else set()

            for v in violations:
                # chp.adapters.http is the sanctioned transport — it alone may
                # import an HTTP client.
                if v.rule == "raw_http" and adapter_id == _HTTP_TRANSPORT_ADAPTER:
                    continue
                if v.rule not in baseline_rules:
                    new_violations.append({**v.to_dict(), "file": str(path)})

        ok = len(new_violations) == 0
        ctx.emit("staged_checked", {
            "files_checked": len(files_checked),
            "new_violation_count": len(new_violations),
            "ok": ok,
        }, redacted=False)
        return {
            "ok": ok,
            "new_violations": new_violations,
            "files_checked": files_checked,
        }

    @capability(
        id="chp.adapters.conformance.close_dev_session",
        emits=_EMITS,
        version="1.0.0",
        description="Close the active dev session: run final conformance scan, compare vs baseline, delete session state.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "outcome": {
                    "type": "string",
                    "enum": ["success", "abandoned"],
                    "description": "Whether the work was completed or abandoned",
                },
                "repo_path": {"type": "string", "description": "Repo/worktree path keying the session (defaults to global)"},
            },
            "additionalProperties": False,
        },
    )
    async def close_dev_session(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        session_file = _session_file(payload.get("repo_path"))
        if not session_file.exists():
            raise RuntimeError("No active dev session to close")

        session_data = json.loads(session_file.read_text())
        issue_id = session_data["issue_id"]
        started_at = session_data.get("started_at", "")
        baseline_total = session_data.get("baseline", {}).get("total_violations", 0)
        outcome = payload.get("outcome", "success")

        duration_s: int | None = None
        if started_at:
            try:
                start = datetime.fromisoformat(started_at)
                duration_s = int((datetime.now(timezone.utc) - start).total_seconds())
            except ValueError:
                duration_s = None  # malformed started_at — skip duration

        final = await self._run_baseline(ctx)
        violations_resolved = max(0, baseline_total - final["total_violations"])

        # Delete session state (sanctioned local state)
        session_file.unlink()

        ctx.emit("dev_session_closed", {
            "issue_id": issue_id,
            "outcome": outcome,
            "duration_s": duration_s,
            "violations_resolved": violations_resolved,
            "violations_remaining": final["total_violations"],
        }, redacted=False)
        return {
            "issue_id": issue_id,
            "outcome": outcome,
            "duration_s": duration_s,
            "violations_resolved": violations_resolved,
            "violations_remaining": final["total_violations"],
            "final_adapter_count": final["adapter_count"],
        }

    @capability(
        id="chp.adapters.conformance.report_violations",
        emits=_EMITS,
        version="1.0.0",
        description="Auto-open Radicle issues for adapters with conformance violations. Deduplicates against existing open issues.",
        category="core",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, report what would be opened without actually opening issues",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
    )
    async def report_violations(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("ConformanceAdapter must be registered with a host")

        dry_run = payload.get("dry_run", False)

        all_results = await self._run_baseline(ctx)
        adapters_with_violations = [r for r in all_results["adapters"] if r["violation_count"] > 0]

        # Fetch existing open issues to deduplicate
        existing_titles: set[str] = set()
        if not dry_run:
            issues_result = await ctx.ainvoke(
                "chp.adapters.radicle.issue_list",
                {"state": "open"},
            )
            if issues_result.success:
                for issue in issues_result.data.get("issues", []):
                    existing_titles.add(issue.get("title", ""))

        issues_opened: list[dict] = []
        issues_existing: list[str] = []

        for adapter_result in adapters_with_violations:
            adapter_id = adapter_result["adapter_id"]
            title = f"fix: conformance violations in {adapter_id}"

            if any(adapter_id in t for t in existing_titles):
                issues_existing.append(adapter_id)
                continue

            violation_lines = "\n".join(
                f"- [{v['severity'].upper()}] {v['rule']}: {v['message']} ({v['location']})"
                for v in adapter_result["violations"]
            )
            body = (
                f"Score: {adapter_result['score']}/100  "
                f"Violations: {adapter_result['violation_count']}\n\n"
                f"{violation_lines}"
            )

            if not dry_run:
                open_result = await ctx.ainvoke(
                    "chp.adapters.radicle.issue_open",
                    {"title": title, "body": body, "labels": ["conformance", "p2"]},
                )
                opened_id = open_result.data.get("issue_id", "") if open_result.success else ""
                issues_opened.append({"adapter_id": adapter_id, "issue_id": opened_id})
            else:
                issues_opened.append({"adapter_id": adapter_id, "title": title, "dry_run": True})

        ctx.emit("violations_reported", {
            "adapters_with_violations": len(adapters_with_violations),
            "issues_opened": len(issues_opened),
            "issues_existing": len(issues_existing),
            "dry_run": dry_run,
        }, redacted=False)
        return {
            "issues_opened": issues_opened,
            "issues_existing": issues_existing,
            "adapters_checked": all_results["adapter_count"],
            "total_violations": all_results["total_violations"],
            "dry_run": dry_run,
        }
