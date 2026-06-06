"""Direct-call coverage tests for CLI modules.

These call CLI command functions directly (not via subprocess) to ensure
coverage is measurable in a clean install environment where subprocess
calls to 'chp ...' don't contribute to pytest-cov metrics.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core.cli._delegation import cmd_delegation_show
from chp_core.cli._registry import (
    cmd_registry_add,
    cmd_registry_list,
    cmd_registry_remove,
    cmd_registry_status,
)
from chp_core.cli._session import (
    _build_session_node,
    cmd_session_autonomy_report,
    cmd_session_export,
    cmd_session_list,
    cmd_session_replay,
    cmd_session_show,
    cmd_session_tree,
)
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import new_id


# ── Helpers ───────────────────────────────────────────────────────────────────


def _args(**kwargs):
    return SimpleNamespace(**kwargs)


def _store(path: str) -> SQLiteEvidenceStore:
    return SQLiteEvidenceStore(path)


def _populate(store_path: str, session_id: str, n_tool_events: int = 2) -> None:
    """Emit a minimal session worth of evidence into the store."""
    from chp_core import LocalCapabilityHost, CapabilityDescriptor, CapabilityCategory

    store_obj = _store(store_path)
    host = LocalCapabilityHost("test-host", store=store_obj)

    async def _noop(ctx, payload):
        return {"ok": True}

    host.register(
        CapabilityDescriptor(
            id="claude_code.bash",
            version="1.0.0",
            description="Bash",
            category=CapabilityCategory.AGENT_OPERATIONS,
        ),
        _noop,
    )
    for _ in range(n_tool_events):
        host.invoke(
            "claude_code.bash",
            {"tool_input": {"command": "echo hi"}},
            correlation_id=session_id,
        )
    store_obj.close()


# ── Session: list ─────────────────────────────────────────────────────────────


class SessionListTests(unittest.TestCase):
    def test_list_empty_store_returns_0(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            args = _args(store=str(Path(d) / "ev.sqlite"), limit=20)
            rc = cmd_session_list(args)
            self.assertEqual(rc, 0)

    def test_list_missing_store_graceful(self):
        args = _args(store="/tmp/chp-nonexistent-list.sqlite", limit=20)
        rc = cmd_session_list(args)
        self.assertEqual(rc, 0)


# ── Session: replay ───────────────────────────────────────────────────────────


class SessionReplayTests(unittest.TestCase):
    def test_replay_missing_correlation_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            args = _args(store=store_path, session_id="no-such-id")
            rc = cmd_session_replay(args)
            self.assertEqual(rc, 1)

    def test_replay_with_events_returns_0(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")
            _populate(store_path, sid)
            args = _args(store=store_path, session_id=sid)
            rc = cmd_session_replay(args)
            self.assertEqual(rc, 0)


# ── Session: show ─────────────────────────────────────────────────────────────


class SessionShowTests(unittest.TestCase):
    def test_show_missing_session_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            args = _args(store=store_path, session_id="ghost")
            rc = cmd_session_show(args)
            self.assertEqual(rc, 1)

    def test_show_with_bash_events_returns_0(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")
            _populate(store_path, sid, n_tool_events=3)
            args = _args(store=store_path, session_id=sid)
            rc = cmd_session_show(args)
            self.assertEqual(rc, 0)

    def test_show_with_file_tool_populates_files_touched(self):
        import tempfile
        from chp_core import AgentSession

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")

            with AgentSession(session_id=sid, store_path=store_path) as session:
                session.record_tool(
                    tool_name="Read",
                    tool_input={"file_path": "/tmp/example.py"},
                    tool_response={"content": "hi"},
                )

            args = _args(store=store_path, session_id=sid)
            out = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = out
            try:
                rc = cmd_session_show(args)
            finally:
                sys.stdout = old_stdout

            self.assertEqual(rc, 0)
            data = json.loads(out.getvalue())
            self.assertIn("/tmp/example.py", data["files_touched"])

    def test_show_computes_duration_with_timestamps(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")
            _populate(store_path, sid, n_tool_events=2)
            args = _args(store=store_path, session_id=sid)
            out = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = out
            try:
                cmd_session_show(args)
            finally:
                sys.stdout = old_stdout
            data = json.loads(out.getvalue())
            self.assertIn("duration_seconds", data)


# ── Session: tree ─────────────────────────────────────────────────────────────


class SessionTreeTests(unittest.TestCase):
    def test_tree_returns_0_for_any_session(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            args = _args(store=store_path, session_id="any-id", depth=2)
            rc = cmd_session_tree(args)
            self.assertEqual(rc, 0)

    def test_tree_depth_zero_truncates(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            node = _build_session_node("s1", store_path, 0, set())
            self.assertTrue(node["truncated"])

    def test_tree_visited_set_prevents_cycles(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            visited = {"s1"}
            node = _build_session_node("s1", store_path, 5, visited)
            self.assertTrue(node["truncated"])


# ── Session: export ───────────────────────────────────────────────────────────


class SessionExportTests(unittest.TestCase):
    def test_export_missing_session_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            args = _args(store=store_path, session_id="ghost", output=None)
            rc = cmd_session_export(args)
            self.assertEqual(rc, 1)

    def test_export_with_events_returns_valid_bundle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")
            _populate(store_path, sid)
            args = _args(store=store_path, session_id=sid, output=None)
            out = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = out
            try:
                rc = cmd_session_export(args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            bundle = json.loads(out.getvalue())
            self.assertEqual(bundle["format"], "chp-session-bundle/1")
            self.assertEqual(bundle["session_id"], sid)
            self.assertGreater(bundle["event_count"], 0)

    def test_export_to_file_writes_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            out_path = str(Path(d) / "export.json")
            sid = new_id("sess")
            _populate(store_path, sid)
            args = _args(store=store_path, session_id=sid, output=out_path)
            rc = cmd_session_export(args)
            self.assertEqual(rc, 0)
            self.assertTrue(Path(out_path).exists())
            data = json.loads(Path(out_path).read_text())
            self.assertEqual(data["session_id"], sid)


# ── Session: autonomy-report ──────────────────────────────────────────────────


class SessionAutonomyReportTests(unittest.TestCase):
    def test_no_autonomy_events_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            sid = new_id("sess")
            _populate(store_path, sid)
            args = _args(store=store_path, session_id=sid)
            rc = cmd_session_autonomy_report(args)
            self.assertEqual(rc, 1)

    def test_autonomy_events_present_returns_0(self):
        import tempfile
        from chp_core import LocalCapabilityHost, CapabilityDescriptor, CapabilityCategory
        from chp_core.types import AutonomyProfile

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            store_obj = _store(store_path)
            host = LocalCapabilityHost("test-host", store=store_obj)

            async def _noop(ctx, p): return {}

            host.register(CapabilityDescriptor(
                id="test.gated", version="1.0.0",
                description="Gated",
                category=CapabilityCategory.AGENT_OPERATIONS,
                autonomy=AutonomyProfile(tier="approval_required"),
            ), _noop)

            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            store_obj.close()

            args = _args(store=store_path, session_id=sid)
            rc = cmd_session_autonomy_report(args)
            self.assertEqual(rc, 0)


# ── Delegation: show ──────────────────────────────────────────────────────────


class DelegationShowTests(unittest.TestCase):
    def test_show_no_events_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            s = _store(store_path); s.close()
            args = _args(store=store_path, correlation_id="no-such")
            rc = cmd_delegation_show(args)
            self.assertEqual(rc, 1)

    def test_show_with_delegation_events_returns_0(self):
        import tempfile
        from chp_core.delegation import DelegationContext
        from chp_core.types import DelegationEnvelope

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            env = DelegationEnvelope(
                delegation_id=new_id("del"),
                from_session="session-a",
                to_agent="agent-b",
                work_parcel="write tests",
            )
            with DelegationContext(env, store_path=store_path) as ctx:
                ctx.accept()
                ctx.complete()

            args = _args(store=store_path, correlation_id=ctx.correlation_id)
            rc = cmd_delegation_show(args)
            self.assertEqual(rc, 0)


# ── Registry: list / add / remove / status ────────────────────────────────────


class RegistryCommandTests(unittest.TestCase):
    def test_registry_list_empty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            reg = str(Path(d) / "registry.json")
            args = _args(registry=reg)
            rc = cmd_registry_list(args)
            self.assertEqual(rc, 0)

    def test_registry_add_then_list(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            reg = str(Path(d) / "registry.json")
            add_args = _args(
                registry=reg, adapter_id="my-adapter", package="mypkg",
                version="1.0.0", disabled=False, tags=["test"],
            )
            rc = cmd_registry_add(add_args)
            self.assertEqual(rc, 0)

            list_args = _args(registry=reg)
            out = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = out
            try:
                cmd_registry_list(list_args)
            finally:
                sys.stdout = old_stdout
            entries = json.loads(out.getvalue())
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["id"], "my-adapter")

    def test_registry_remove_existing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            reg = str(Path(d) / "registry.json")
            cmd_registry_add(_args(
                registry=reg, adapter_id="rm-me", package="pkg",
                version="1.0.0", disabled=False, tags=[],
            ))
            rc = cmd_registry_remove(_args(registry=reg, adapter_id="rm-me"))
            self.assertEqual(rc, 0)

    def test_registry_remove_nonexistent_returns_1(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            reg = str(Path(d) / "registry.json")
            rc = cmd_registry_remove(_args(registry=reg, adapter_id="ghost"))
            self.assertEqual(rc, 1)

    def test_registry_status_empty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            reg = str(Path(d) / "registry.json")
            args = _args(registry=reg)
            rc = cmd_registry_status(args)
            self.assertEqual(rc, 0)


# ── Hooks: install / status / uninstall ──────────────────────────────────────


class HooksInstallTests(unittest.TestCase):
    def test_install_precommit_hook_creates_file(self):
        import tempfile, os, stat
        from chp_core.cli._hooks import _install_precommit_hook

        with tempfile.TemporaryDirectory() as d:
            git_hooks = Path(d) / ".git" / "hooks"
            git_hooks.mkdir(parents=True)
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                path = _install_precommit_hook()
            finally:
                os.chdir(old_cwd)
            self.assertTrue(Path(path).exists())
            mode = Path(path).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR)

    def test_install_prepush_hook_creates_file(self):
        import tempfile, os, stat
        from chp_core.cli._hooks import _install_prepush_hook

        with tempfile.TemporaryDirectory() as d:
            git_hooks = Path(d) / ".git" / "hooks"
            git_hooks.mkdir(parents=True)
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                path = _install_prepush_hook()
            finally:
                os.chdir(old_cwd)
            self.assertTrue(Path(path).exists())
            mode = Path(path).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR)

    def test_install_precommit_raises_without_git_dir(self):
        import tempfile, os
        from chp_core.cli._hooks import _install_precommit_hook

        with tempfile.TemporaryDirectory() as d:
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                with self.assertRaises(FileNotFoundError):
                    _install_precommit_hook()
            finally:
                os.chdir(old_cwd)

    def test_hooks_status_exits_0_no_settings(self):
        import tempfile, os
        from chp_core.cli._hooks import cmd_hooks_status

        with tempfile.TemporaryDirectory() as d:
            fake_settings = str(Path(d) / "settings.json")
            args = _args(global_scope=False, project=False)
            # Patch _settings_path to return non-existent path
            import chp_core.cli._hooks as hooks_mod
            original = hooks_mod._settings_path
            hooks_mod._settings_path = lambda *_: fake_settings
            try:
                rc = cmd_hooks_status(args)
            finally:
                hooks_mod._settings_path = original
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
