"""CIAdapter — run package test suites as governed CHP capability invocations.

Each package's pytest run becomes a ctx.ainvoke("chp.adapters.ci.run_suite")
call so it appears as a first-class record in the correlation chain. The
run_all capability orchestrates the full suite via the lego-block pattern:
  run_all → ctx.ainvoke(run_suite) × N packages → evidence per package

Evidence policy:
  Emitted: package name, path, pass/fail counts, duration, exit code, summary.
  NOT emitted: test output, failure messages (may contain paths or secrets).
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "ci_run_started",
    "ci_run_completed",
    "ci_suite_started",
    "ci_suite_completed",
    "ci_suite_failed",
]

_PASSED_RE = re.compile(r"(\d+) passed")
_FAILED_RE = re.compile(r"(\d+) failed")
_ERROR_RE  = re.compile(r"(\d+) error")


@dataclass
class CIConfig:
    """Config for CIAdapter.

    ``repo_root`` — root of the chp-dev repo; defaults to cwd() at call time.
    ``python`` — Python executable to use for subprocess pytest invocations.
    """

    repo_root: str = ""
    python: str = ""

    def resolved_root(self) -> Path:
        return Path(self.repo_root).expanduser().resolve() if self.repo_root else Path.cwd()

    def resolved_python(self) -> str:
        return self.python or sys.executable


class CIAdapter(BaseAdapter):
    """Run package test suites as governed CHP invocations with per-suite evidence."""

    adapter_id = "chp.adapters.ci"
    adapter_name = "CI"
    adapter_description = "Run pytest across CHP packages as governed capability calls. Each suite is a separate evidence-producing invocation."
    adapter_category = "developer_tooling"
    adapter_tags = ["ci", "testing", "pytest", "quality", "evidence"]

    def __init__(self, config: CIConfig | None = None) -> None:
        self._config = config or CIConfig()

    def _discover_packages(self) -> list[dict[str, str]]:
        """Find all packages under repo_root/packages/ that have a pyproject.toml."""
        packages_dir = self._config.resolved_root() / "packages"
        if not packages_dir.is_dir():
            return []
        return sorted(
            [
                {"name": p.name, "path": str(p)}
                for p in packages_dir.iterdir()
                if p.is_dir() and (p / "pyproject.toml").exists()
            ],
            key=lambda x: x["name"],
        )

    # ------------------------------------------------------------------
    # run_suite
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.ci.run_suite",
        version="1.0.0",
        description="Run pytest for a single package and emit pass/fail evidence. Output is not recorded — only counts and duration.",
        category="developer_tooling",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "package_name": {"type": "string", "description": "Human-readable package name (e.g. chp-adapter-messages)"},
                "package_path": {"type": "string", "description": "Absolute path to the package directory"},
            },
            "required": ["package_name", "package_path"],
            "additionalProperties": False,
        },
    )
    async def run_suite(self, ctx: Any, payload: dict) -> dict:
        package_name: str = payload["package_name"]
        package_path: str = payload["package_path"]

        ctx.emit("ci_suite_started", {
            "package": package_name,
            "path": package_path,
        }, redacted=False)

        t0 = time.monotonic()
        result = subprocess.run(
            [self._config.resolved_python(), "-m", "pytest", "-q", "-o", "addopts="],
            cwd=package_path,
            capture_output=True,
            text=True,
        )
        duration_ms = round((time.monotonic() - t0) * 1000)

        output = (result.stdout + result.stderr).strip()
        summary_line = next(
            (ln for ln in reversed(output.splitlines()) if ln.strip()),
            "",
        )

        passed = int(m.group(1)) if (m := _PASSED_RE.search(summary_line)) else 0
        failed = int(m.group(1)) if (m := _FAILED_RE.search(summary_line)) else 0
        errors = int(m.group(1)) if (m := _ERROR_RE.search(summary_line)) else 0
        ok = result.returncode == 0

        evidence = {
            "package": package_name,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "duration_ms": duration_ms,
            "exit_code": result.returncode,
            "summary": summary_line[:200],
        }

        if ok:
            ctx.emit("ci_suite_completed", evidence, redacted=False)
        else:
            ctx.emit("ci_suite_failed", evidence, redacted=False)

        return {"ok": ok, **evidence}

    # ------------------------------------------------------------------
    # run_all
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.ci.run_all",
        version="1.0.0",
        description="Run pytest across all packages in the repo. Each suite is a separate ctx.ainvoke(run_suite) call — every package gets its own evidence record.",
        category="developer_tooling",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "packages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Package names to run (default: all discovered packages)",
                },
            },
            "additionalProperties": False,
        },
    )
    async def run_all(self, ctx: Any, payload: dict) -> dict:
        all_packages = self._discover_packages()
        filter_names: list[str] | None = payload.get("packages") or None

        packages = (
            [p for p in all_packages if p["name"] in filter_names]
            if filter_names
            else all_packages
        )

        ctx.emit("ci_run_started", {
            "package_count": len(packages),
            "packages": [p["name"] for p in packages],
        }, redacted=False)

        suite_results: list[dict] = []
        for pkg in packages:
            result = await ctx.ainvoke(
                "chp.adapters.ci.run_suite",
                {"package_name": pkg["name"], "package_path": pkg["path"]},
            )
            if result.success:
                suite_results.append(result.data)
            else:
                suite_results.append({
                    "package": pkg["name"],
                    "ok": False,
                    "passed": 0,
                    "failed": 0,
                    "errors": 1,
                    "duration_ms": 0,
                    "exit_code": -1,
                    "summary": str(result.error),
                })

        total_passed = sum(r.get("passed", 0) for r in suite_results)
        total_failed = sum(r.get("failed", 0) + r.get("errors", 0) for r in suite_results)
        failed_suites = [r["package"] for r in suite_results if not r.get("ok")]
        ok = len(failed_suites) == 0

        ctx.emit("ci_run_completed", {
            "ok": ok,
            "total_packages": len(packages),
            "total_passed": total_passed,
            "total_failed": total_failed,
            "failed_suites": failed_suites,
        }, redacted=False)

        return {
            "ok": ok,
            "total_packages": len(packages),
            "total_passed": total_passed,
            "total_failed": total_failed,
            "failed_suites": failed_suites,
            "suites": suite_results,
        }
