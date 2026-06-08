"""Smoke tests for the chp CLI entry point.

These verify that the installed CLI is reachable and that key subcommand
groups respond correctly — without exercising full functionality.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "chp_core.cli", *args],
        capture_output=True,
        text=True,
    )


class CLIEntryPointTests(unittest.TestCase):
    def test_help_exits_0(self) -> None:
        result = _run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("chp", result.stdout)

    def test_hook_group_help(self) -> None:
        result = _run("hook", "--help")
        self.assertEqual(result.returncode, 0)

    def test_hooks_group_help(self) -> None:
        result = _run("hooks", "--help")
        self.assertEqual(result.returncode, 0)

    def test_session_group_help(self) -> None:
        result = _run("session", "--help")
        self.assertEqual(result.returncode, 0)

    def test_hooks_status_exits_0(self) -> None:
        # May or may not find a settings.json — both outcomes are exit 0
        result = _run("hooks", "status")
        self.assertEqual(result.returncode, 0)

    def test_session_list_with_nonexistent_store_exits_gracefully(self) -> None:
        result = _run("session", "list", "--store", "/tmp/chp-nonexistent-smoke-test.sqlite")
        # Should exit 0 with "No sessions found." — not crash
        self.assertEqual(result.returncode, 0)

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        result = _run("definitely-not-a-command")
        self.assertNotEqual(result.returncode, 0)

    def test_host_group_help(self) -> None:
        result = _run("host", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("verify", result.stdout)

    def test_serve_http_help(self) -> None:
        result = _run("serve-http", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--module", result.stdout)


class HostVerifyTests(unittest.TestCase):
    def test_host_verify_exits_0(self) -> None:
        result = _run("host", "verify")
        self.assertEqual(result.returncode, 0)
        self.assertIn("healthy", result.stdout)

    def test_host_verify_with_store_dir(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            result = _run("host", "verify", "--store-dir", d)
            self.assertEqual(result.returncode, 0)
            self.assertIn("healthy", result.stdout)

    def test_serve_http_missing_module_exits_nonzero(self) -> None:
        result = _run("serve-http", "--module", "nonexistent.module:create_host")
        self.assertNotEqual(result.returncode, 0)

    def test_serve_http_bad_module_spec_exits_nonzero(self) -> None:
        result = _run("serve-http", "--module", "no_colon_in_here")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
