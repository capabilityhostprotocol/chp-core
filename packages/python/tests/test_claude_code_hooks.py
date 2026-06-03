from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore, register_adapter
from chp_core.adapters.claude_code import ClaudeCodeAdapter
from chp_core.hooks import (
    capability_id_for_tool,
    default_store_path,
    process_post_tool_use,
    process_stop,
)


def _store() -> SQLiteEvidenceStore:
    return SQLiteEvidenceStore(":memory:")


def _post_tool(
    tool_name: str = "Bash",
    tool_input: dict | None = None,
    tool_response: dict | None = None,
    session_id: str = "sess-001",
    cwd: str = "/tmp",
) -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": tool_input or {"command": "echo hi"},
        "tool_response": tool_response or {"output": "hi", "error": None},
        "cwd": cwd,
    }


class HookToolMappingTests(unittest.TestCase):
    def test_known_tools_map_correctly(self) -> None:
        self.assertEqual(capability_id_for_tool("Bash"), "claude_code.bash")
        self.assertEqual(capability_id_for_tool("Read"), "claude_code.read")
        self.assertEqual(capability_id_for_tool("Edit"), "claude_code.edit")
        self.assertEqual(capability_id_for_tool("Write"), "claude_code.write")
        self.assertEqual(capability_id_for_tool("Agent"), "claude_code.agent")
        self.assertEqual(capability_id_for_tool("WebFetch"), "claude_code.web_fetch")

    def test_mcp_tool_mapping(self) -> None:
        self.assertEqual(
            capability_id_for_tool("mcp__memory__create_entities"),
            "claude_code.mcp.memory.create_entities",
        )
        self.assertEqual(
            capability_id_for_tool("mcp__gitnexus__query"),
            "claude_code.mcp.gitnexus.query",
        )

    def test_unknown_tool_fallback(self) -> None:
        self.assertEqual(capability_id_for_tool("SomeFutureTool"), "claude_code.tool.somefuturetool")


class PostToolUseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = _store()

    def tearDown(self) -> None:
        self.store.close()

    def _run(self, payload: dict, store_path: str = ":memory:") -> None:
        process_post_tool_use(payload, store_path)

    def _events(self, session_id: str = "sess-001") -> list[dict]:
        return self.store.by_correlation(session_id)

    def test_post_tool_use_emits_tool_use_evidence(self) -> None:
        process_post_tool_use(_post_tool(), ":memory:")
        # Can't inspect :memory: store after process_post_tool_use (new connection each time).
        # Use a shared store path via a temp file approach — test via dedicated store param.
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_post_tool_use(_post_tool(session_id="sess-emit"), path)
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-emit")
            store.close()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "tool_use")
            self.assertEqual(events[0]["capability_id"], "claude_code.bash")
        finally:
            os.unlink(path)

    def test_post_tool_use_bash_outcome_success(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_post_tool_use(
                _post_tool(tool_response={"output": "ok", "error": None, "exit_code": 0}),
                path,
            )
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-001")
            store.close()
            self.assertEqual(events[0]["outcome"], "success")
        finally:
            os.unlink(path)

    def test_post_tool_use_bash_outcome_failure(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_post_tool_use(
                _post_tool(tool_response={"output": "", "error": "command not found", "exit_code": 127}),
                path,
            )
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-001")
            store.close()
            self.assertEqual(events[0]["outcome"], "failure")
        finally:
            os.unlink(path)

    def test_post_tool_use_mcp_tool_capability_id(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_post_tool_use(
                _post_tool(tool_name="mcp__gitnexus__query", session_id="sess-mcp"),
                path,
            )
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-mcp")
            store.close()
            self.assertEqual(events[0]["capability_id"], "claude_code.mcp.gitnexus.query")
        finally:
            os.unlink(path)

    def test_tool_input_is_redacted(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_post_tool_use(
                _post_tool(
                    tool_input={"command": "curl -H 'Authorization: Bearer secret-token' https://api.example.com"},
                    session_id="sess-redact",
                ),
                path,
            )
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-redact")
            store.close()
            # The tool_input dict key is "command" (not a sensitive key), so it's not redacted.
            # But if the input dict contained "authorization": "secret", it would be.
            process_post_tool_use(
                _post_tool(
                    tool_input={"authorization": "Bearer secret-token", "url": "https://api.example.com"},
                    session_id="sess-redact-keys",
                ),
                path,
            )
            store2 = SQLiteEvidenceStore(path)
            events2 = store2.by_correlation("sess-redact-keys")
            store2.close()
            self.assertEqual(events2[0]["payload"]["tool_input"]["authorization"], "[REDACTED]")
            self.assertEqual(events2[0]["payload"]["tool_input"]["url"], "https://api.example.com")
        finally:
            os.unlink(path)


class StopHookTests(unittest.TestCase):
    def test_stop_emits_session_completed(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            process_stop(
                {"hook_event_name": "Stop", "session_id": "sess-stop", "transcript_path": "/tmp/t.jsonl"},
                path,
            )
            store = SQLiteEvidenceStore(path)
            events = store.by_correlation("sess-stop")
            store.close()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "session_completed")
            self.assertEqual(events[0]["payload"]["transcript_path"], "/tmp/t.jsonl")
        finally:
            os.unlink(path)

    def test_session_correlation(self) -> None:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            sid = "sess-corr"
            for i in range(3):
                process_post_tool_use(_post_tool(session_id=sid), path)
            process_stop({"hook_event_name": "Stop", "session_id": sid, "transcript_path": ""}, path)

            store = SQLiteEvidenceStore(path)
            events = store.by_correlation(sid)
            store.close()

            self.assertEqual(len(events), 4)
            event_types = [e["event_type"] for e in events]
            self.assertEqual(event_types.count("tool_use"), 3)
            self.assertEqual(event_types.count("session_completed"), 1)
            # tool_count in session_completed should equal 3
            session_ev = next(e for e in events if e["event_type"] == "session_completed")
            self.assertEqual(session_ev["payload"]["tool_count"], 3)
        finally:
            os.unlink(path)


class ClaudeCodeAdapterTests(unittest.TestCase):
    def test_adapter_registers_all_capabilities(self) -> None:
        host = LocalCapabilityHost("test-cc", store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, ClaudeCodeAdapter())
        discovered = host.discover()
        ids = {c["id"] for c in discovered["capabilities"]}
        self.assertIn("claude_code.bash", ids)
        self.assertIn("claude_code.read", ids)
        self.assertIn("claude_code.edit", ids)
        self.assertIn("claude_code.agent", ids)
        self.assertIn("claude_code.session", ids)
        self.assertIn("claude_code.web_fetch", ids)
        self.assertIn("claude_code.mcp_tool", ids)

    def test_adapter_risk_tiers(self) -> None:
        host = LocalCapabilityHost("test-cc-risk", store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, ClaudeCodeAdapter())
        caps = {c["id"]: c for c in host.discover()["capabilities"]}
        self.assertEqual(caps["claude_code.bash"]["risk"], "medium")
        self.assertEqual(caps["claude_code.read"]["risk"], "low")
        self.assertEqual(caps["claude_code.edit"]["risk"], "medium")
        self.assertEqual(caps["claude_code.web_fetch"]["risk"], "low")


class HooksInstallTests(unittest.TestCase):
    def test_hooks_install_writes_settings(self) -> None:
        import tempfile, os, json
        settings = {"hooks": {"PreToolUse": [], "Stop": []}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(settings, f)
            path = f.name
        try:
            from chp_core.cli import _install_hooks
            _install_hooks(path)
            with open(path) as f:
                updated = json.load(f)
            post_commands = [
                h["command"]
                for entry in updated["hooks"].get("PostToolUse", [])
                for h in entry.get("hooks", [])
                if h.get("type") == "command"
            ]
            self.assertIn("chp hook post-tool", post_commands)
            stop_commands = [
                h["command"]
                for entry in updated["hooks"].get("Stop", [])
                for h in entry.get("hooks", [])
                if h.get("type") == "command"
            ]
            self.assertIn("chp hook stop", stop_commands)
        finally:
            os.unlink(path)

    def test_hooks_install_is_idempotent(self) -> None:
        import tempfile, os, json
        settings = {"hooks": {}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(settings, f)
            path = f.name
        try:
            from chp_core.cli import _install_hooks
            _install_hooks(path)
            _install_hooks(path)
            with open(path) as f:
                updated = json.load(f)
            post_commands = [
                h["command"]
                for entry in updated["hooks"].get("PostToolUse", [])
                for h in entry.get("hooks", [])
                if h.get("type") == "command"
            ]
            self.assertEqual(post_commands.count("chp hook post-tool"), 1)
        finally:
            os.unlink(path)


class HookPerformanceTests(unittest.TestCase):
    @unittest.skipIf(False, "perf")  # always runs; pytest -m perf selects it explicitly
    def test_post_tool_use_completes_under_5ms(self) -> None:
        import os
        import tempfile
        import time

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            # Warm up (first call initialises the schema)
            process_post_tool_use(_post_tool(session_id="warmup"), path)
            # Measured call
            start = time.perf_counter()
            process_post_tool_use(_post_tool(session_id="perf-test"), path)
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.assertLess(elapsed_ms, 5.0, f"hook took {elapsed_ms:.2f}ms — limit is 5ms")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
