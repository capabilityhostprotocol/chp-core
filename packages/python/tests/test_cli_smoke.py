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


if __name__ == "__main__":
    unittest.main()
