"""Tests for chp-adapter-ci."""

from __future__ import annotations

import asyncio
import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chp_adapter_ci import CIAdapter, CIConfig
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host(repo_root: str = "") -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    config = CIConfig(repo_root=repo_root)
    register_adapter(host, CIAdapter(config))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(
        host.ainvoke(cap_id, payload or {})
    )


def _fake_run(returncode: int = 0, stdout: str = "1 passed in 0.1s", stderr: str = ""):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


# ---------------------------------------------------------------------------
# CIConfig
# ---------------------------------------------------------------------------

class TestCIConfig:
    def test_resolved_root_defaults_to_cwd(self):
        config = CIConfig()
        assert config.resolved_root() == Path.cwd()

    def test_resolved_root_expands_path(self, tmp_path):
        config = CIConfig(repo_root=str(tmp_path))
        assert config.resolved_root() == tmp_path

    def test_resolved_python_defaults_to_sys(self):
        import sys
        config = CIConfig()
        assert config.resolved_python() == sys.executable

    def test_resolved_python_uses_override(self):
        config = CIConfig(python="/custom/python3")
        assert config.resolved_python() == "/custom/python3"


# ---------------------------------------------------------------------------
# CIAdapter._discover_packages
# ---------------------------------------------------------------------------

class TestDiscoverPackages:
    def test_finds_packages_with_pyproject(self, tmp_path):
        pkg_a = tmp_path / "packages" / "pkg-a"
        pkg_a.mkdir(parents=True)
        (pkg_a / "pyproject.toml").write_text("[project]\nname = 'pkg-a'\n")

        pkg_b = tmp_path / "packages" / "pkg-b"
        pkg_b.mkdir(parents=True)
        (pkg_b / "pyproject.toml").write_text("[project]\nname = 'pkg-b'\n")

        no_toml = tmp_path / "packages" / "not-a-package"
        no_toml.mkdir(parents=True)

        adapter = CIAdapter(CIConfig(repo_root=str(tmp_path)))
        packages = adapter._discover_packages()

        names = [p["name"] for p in packages]
        assert "pkg-a" in names
        assert "pkg-b" in names
        assert "not-a-package" not in names

    def test_returns_empty_when_no_packages_dir(self, tmp_path):
        adapter = CIAdapter(CIConfig(repo_root=str(tmp_path)))
        assert adapter._discover_packages() == []

    def test_sorted_alphabetically(self, tmp_path):
        for name in ["pkg-z", "pkg-a", "pkg-m"]:
            d = tmp_path / "packages" / name
            d.mkdir(parents=True)
            (d / "pyproject.toml").write_text("")

        adapter = CIAdapter(CIConfig(repo_root=str(tmp_path)))
        names = [p["name"] for p in adapter._discover_packages()]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# run_suite capability
# ---------------------------------------------------------------------------

class TestRunSuite:
    def test_passing_suite(self, tmp_path):
        host = _make_host()
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run(0, "3 passed in 0.42s")
            result = _invoke(host, "chp.adapters.ci.run_suite", {
                "package_name": "my-pkg",
                "package_path": str(tmp_path),
            })

        assert result.success
        assert result.data["ok"] is True
        assert result.data["passed"] == 3
        assert result.data["failed"] == 0
        assert result.data["exit_code"] == 0
        assert result.data["package"] == "my-pkg"

    def test_failing_suite(self, tmp_path):
        host = _make_host()
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run(1, "2 passed, 1 failed in 0.5s")
            result = _invoke(host, "chp.adapters.ci.run_suite", {
                "package_name": "bad-pkg",
                "package_path": str(tmp_path),
            })

        assert result.success
        assert result.data["ok"] is False
        assert result.data["passed"] == 2
        assert result.data["failed"] == 1
        assert result.data["exit_code"] == 1

    def test_summary_truncated_at_200(self, tmp_path):
        host = _make_host()
        long_line = "x" * 300
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run(0, long_line)
            result = _invoke(host, "chp.adapters.ci.run_suite", {
                "package_name": "pkg",
                "package_path": str(tmp_path),
            })

        assert len(result.data["summary"]) <= 200

    def test_duration_ms_positive(self, tmp_path):
        host = _make_host()
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run()
            result = _invoke(host, "chp.adapters.ci.run_suite", {
                "package_name": "pkg",
                "package_path": str(tmp_path),
            })
        assert result.data["duration_ms"] >= 0

    def test_subprocess_called_with_correct_args(self, tmp_path):
        host = _make_host()
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run()
            _invoke(host, "chp.adapters.ci.run_suite", {
                "package_name": "pkg",
                "package_path": str(tmp_path),
            })

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert "-m" in cmd
        assert "pytest" in cmd
        assert call_args[1]["cwd"] == str(tmp_path)
        assert call_args[1]["capture_output"] is True


# ---------------------------------------------------------------------------
# run_all capability
# ---------------------------------------------------------------------------

class TestRunAll:
    def test_all_pass(self, tmp_path):
        for name in ["pkg-a", "pkg-b"]:
            d = tmp_path / "packages" / name
            d.mkdir(parents=True)
            (d / "pyproject.toml").write_text("")

        host = _make_host(repo_root=str(tmp_path))
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run(0, "5 passed in 0.1s")
            result = _invoke(host, "chp.adapters.ci.run_all", {})

        assert result.success
        assert result.data["ok"] is True
        assert result.data["total_packages"] == 2
        assert result.data["total_passed"] == 10  # 5 per package
        assert result.data["failed_suites"] == []

    def test_one_fails(self, tmp_path):
        for name in ["pkg-ok", "pkg-broken"]:
            d = tmp_path / "packages" / name
            d.mkdir(parents=True)
            (d / "pyproject.toml").write_text("")

        host = _make_host(repo_root=str(tmp_path))

        def side_effect(cmd, cwd=None, **kwargs):
            if "pkg-broken" in str(cwd):
                return _fake_run(1, "1 failed in 0.1s")
            return _fake_run(0, "3 passed in 0.1s")

        with patch("chp_adapter_ci.adapter.subprocess.run", side_effect=side_effect):
            result = _invoke(host, "chp.adapters.ci.run_all", {})

        assert result.success
        assert result.data["ok"] is False
        assert "pkg-broken" in result.data["failed_suites"]
        assert "pkg-ok" not in result.data["failed_suites"]

    def test_package_filter(self, tmp_path):
        for name in ["pkg-a", "pkg-b", "pkg-c"]:
            d = tmp_path / "packages" / name
            d.mkdir(parents=True)
            (d / "pyproject.toml").write_text("")

        host = _make_host(repo_root=str(tmp_path))
        with patch("chp_adapter_ci.adapter.subprocess.run") as mock_run:
            mock_run.return_value = _fake_run()
            result = _invoke(host, "chp.adapters.ci.run_all", {
                "packages": ["pkg-a", "pkg-c"],
            })

        assert result.data["total_packages"] == 2
        ran = {r["package"] for r in result.data["suites"]}
        assert ran == {"pkg-a", "pkg-c"}

    def test_empty_repo_no_packages(self, tmp_path):
        host = _make_host(repo_root=str(tmp_path))
        result = _invoke(host, "chp.adapters.ci.run_all", {})

        assert result.success
        assert result.data["total_packages"] == 0
        assert result.data["ok"] is True


# ---------------------------------------------------------------------------
# Conformance: adapter.py has no violations
# ---------------------------------------------------------------------------

class TestCIAdapterConformance:
    def test_no_conformance_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_ci.adapter as mod
        import inspect

        src_path = inspect.getfile(mod)
        violations = check_source_file(src_path)
        assert not violations, f"CIAdapter has conformance violations: {violations}"
