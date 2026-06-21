"""Tests for chp_adapter_process.adapter."""

from __future__ import annotations

import sys

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_process import ProcessAdapter, ProcessConfig


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _make_host(config=None):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, ProcessAdapter(config))
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


_PYTHON = sys.executable  # path to current Python interpreter


# --------------------------------------------------------------------------
# 1. Shaping
# --------------------------------------------------------------------------

class TestShaping:
    def test_one_capability(self):
        ids = {c.descriptor.id for c in ProcessAdapter().capabilities()}
        assert ids == {"chp.adapters.process.run"}

    def test_run_is_high_risk(self):
        caps = {c.descriptor.id: c.descriptor for c in ProcessAdapter().capabilities()}
        assert caps["chp.adapters.process.run"].risk == "high"

    def test_adapter_id(self):
        assert ProcessAdapter.adapter_id == "chp.adapters.process"


# --------------------------------------------------------------------------
# 2. Success path
# --------------------------------------------------------------------------

class TestSuccessPath:
    def test_echo_succeeds(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "print('hello')"]
        })
        assert r.outcome == "success"
        assert r.data["exit_code"] == 0
        assert "hello" in r.data["stdout"]
        assert r.data["timed_out"] is False

    def test_exit_code_captured(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "import sys; sys.exit(42)"]
        })
        assert r.outcome == "success"
        assert r.data["exit_code"] == 42

    def test_stderr_captured(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON,
            "args": ["-c", "import sys; sys.stderr.write('err-output')"]
        })
        assert r.outcome == "success"
        assert "err-output" in r.data["stderr"]

    def test_duration_ms_positive(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        assert r.data["duration_ms"] >= 0


# --------------------------------------------------------------------------
# 3. Allowlist
# --------------------------------------------------------------------------

class TestAllowlist:
    def test_command_not_in_allowlist_fails(self):
        host = _make_host(ProcessConfig(allowed_commands=["echo"]))
        r = host.invoke("chp.adapters.process.run", {"command": _PYTHON, "args": ["-c", "pass"]})
        assert r.outcome == "failure"

    def test_command_in_allowlist_succeeds(self):
        host = _make_host(ProcessConfig(allowed_commands=[_PYTHON]))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        assert r.outcome == "success"

    def test_none_allowlist_permits_all(self):
        host = _make_host(ProcessConfig(allowed_commands=None))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        assert r.outcome == "success"


# --------------------------------------------------------------------------
# 4. Timeout
# --------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_kills_process(self):
        host = _make_host(ProcessConfig(max_timeout=0.5))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON,
            "args": ["-c", "import time; time.sleep(10)"],
            "timeout": 0.3,
        })
        assert r.outcome == "success"
        assert r.data["timed_out"] is True
        assert r.data["exit_code"] == -1

    def test_timeout_capped_at_max(self):
        host = _make_host(ProcessConfig(max_timeout=5.0))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"],
            "timeout": 999.0,
        })
        assert r.outcome == "success"
        assert r.data["timed_out"] is False


# --------------------------------------------------------------------------
# 5. cwd restriction
# --------------------------------------------------------------------------

class TestCwdRestriction:
    def test_cwd_outside_working_dir_fails(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        host = _make_host(ProcessConfig(working_dir=str(allowed)))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"],
            "cwd": str(tmp_path),
        })
        assert r.outcome == "failure"

    def test_cwd_inside_working_dir_succeeds(self, tmp_path):
        host = _make_host(ProcessConfig(working_dir=str(tmp_path)))
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"],
            "cwd": str(tmp_path),
        })
        assert r.outcome == "success"


# --------------------------------------------------------------------------
# 6. Unknown command
# --------------------------------------------------------------------------

class TestUnknownCommand:
    def test_command_not_found_fails(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": "definitely_not_a_real_command_xyz123"
        })
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 7. Schema validation
# --------------------------------------------------------------------------

class TestSchema:
    def test_missing_command_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {})
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "injected": "bad"
        })
        assert r.outcome == "denied"

    def test_valid_command_not_denied(self):
        # Regression for rad:72fb420 — valid command must not be denied.
        host = _make_host()
        r = host.invoke("chp.adapters.process.run",
                        {"command": _PYTHON, "args": ["-c", "pass"]})
        assert r.outcome == "success"

    def test_valid_payload_via_arguments_key(self):
        # from_mapping supports 'arguments' as alias for 'payload'.
        from chp_core.types import InvocationEnvelope
        env = InvocationEnvelope.from_mapping({
            "capability_id": "chp.adapters.process.run",
            "arguments": {"command": _PYTHON, "args": ["-c", "pass"]},
        })
        assert env.payload == {"command": _PYTHON, "args": ["-c", "pass"]}


# --------------------------------------------------------------------------
# 8. Evidence hygiene
# --------------------------------------------------------------------------

class TestEvidenceHygiene:
    def test_env_additions_values_not_in_evidence(self):
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"],
            "env_additions": {"MY_SECRET": "SUPER_SECRET_VALUE_XYZ"},
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "SUPER_SECRET_VALUE_XYZ" not in dump

    def test_env_additions_keys_in_evidence(self):
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"],
            "env_additions": {"MY_SECRET": "value"},
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "MY_SECRET" in dump

    def test_process_start_event_emitted(self):
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "process_start" in types

    def test_process_result_event_emitted(self):
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "process_result" in types

    def test_process_timeout_event_emitted(self):
        host = _make_host(ProcessConfig(max_timeout=0.5))
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON,
            "args": ["-c", "import time; time.sleep(10)"],
            "timeout": 0.3,
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "process_timeout" in types

    def test_no_lifecycle_events_in_evidence(self):
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON, "args": ["-c", "pass"]
        })
        lifecycle = {"execution_started", "execution_completed", "execution_failed"}
        types = {e["event_type"] for e in _cap_events(host.store)}
        assert not types & lifecycle, f"lifecycle events found: {types & lifecycle}"

    def test_stdout_preview_truncated_in_evidence(self):
        big_output = "A" * 2000
        host = _make_host()
        host.invoke("chp.adapters.process.run", {
            "command": _PYTHON,
            "args": ["-c", f"print('{'A' * 2000}')"],
        })
        result_events = [
            e for e in _cap_events(host.store)
            if e["event_type"] == "process_result"
        ]
        assert len(result_events) == 1
        preview = result_events[0]["payload"].get("stdout_preview", "")
        assert len(preview) <= 500
