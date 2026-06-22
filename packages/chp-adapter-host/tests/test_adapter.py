"""Tests for chp-adapter-host."""

from __future__ import annotations

from chp_core import LocalCapabilityHost, register_adapter

from chp_adapter_host import HostAdapter
from chp_adapter_host import adapter as adapter_module


def _host():
    h = LocalCapabilityHost("test")
    register_adapter(h, HostAdapter())
    return h


def test_version_capability():
    result = _host().invoke("chp.adapters.host.version", {})
    assert result.outcome == "success"
    assert "host_version" in result.data
    assert isinstance(result.data["adapters"], list)
    assert "platform" in result.data


def test_update_schedules_detached(monkeypatch):
    calls: dict = {}

    class FakeProc:
        pid = 4242

    def fake_popen(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(adapter_module.subprocess, "Popen", fake_popen)

    result = _host().invoke("chp.adapters.host.update", {"version": "0.8.9", "channel": "pypi"})
    assert result.outcome == "success"
    assert result.data["scheduled"] is True
    assert result.data["pid"] == 4242

    # Detached so it survives the host restart it triggers.
    assert calls["kwargs"].get("start_new_session") is True
    # Shells out to the chp-host update CLI with the right args.
    assert "update" in calls["cmd"] and "--restart" in calls["cmd"]
    assert "--version" in calls["cmd"] and "0.8.9" in calls["cmd"]
    assert "--channel" in calls["cmd"] and "pypi" in calls["cmd"]
