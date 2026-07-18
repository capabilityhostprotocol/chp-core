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


def test_stats_capability_success():
    result = _host().invoke("chp.adapters.host.stats", {})
    assert result.outcome == "success"


def test_stats_capability_has_cpu_count():
    result = _host().invoke("chp.adapters.host.stats", {})
    assert result.outcome == "success"
    assert "cpu_count" in result.data
    assert isinstance(result.data["cpu_count"], int)
    assert result.data["cpu_count"] >= 1


def test_stats_capability_has_load_per_core():
    result = _host().invoke("chp.adapters.host.stats", {})
    assert result.outcome == "success"
    # load_per_core may be None on platforms without getloadavg, but key must exist
    assert "load_per_core" in result.data


def test_stats_capability_has_disk():
    result = _host().invoke("chp.adapters.host.stats", {})
    assert result.outcome == "success"
    disk = result.data.get("disk")
    assert disk is not None
    assert disk["total_gb"] > 0


def test_stats_capability_evidence_recorded():
    result = _host().invoke("chp.adapters.host.stats", {})
    assert result.outcome == "success"
    assert result.evidence_ids


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
    # Shells out to `chp-host update` (restart is the default). It must NOT pass
    # --restart — that's not a valid flag and argparse would kill the child.
    assert "update" in calls["cmd"]
    assert "--restart" not in calls["cmd"]
    assert "--version" in calls["cmd"] and "0.8.9" in calls["cmd"]
    assert "--channel" in calls["cmd"] and "pypi" in calls["cmd"]
    # The child env must carry HOME (services run without it) so pip + logging work.
    assert calls["kwargs"].get("env", {}).get("HOME")


def test_install_adapter_schedules_detached(monkeypatch):
    calls: dict = {}

    class FakeProc:
        pid = 99

    def fake_popen(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(adapter_module.subprocess, "Popen", fake_popen)
    # Pretend this host was started with a profile (so adapter_name → profile edit).
    monkeypatch.setattr(adapter_module.sys, "argv",
                        ["chp-host", "serve", "--profile", "/tmp/inference.json"])

    result = _host().invoke("chp.adapters.host.install_adapter",
                            {"package": "chp-adapter-mlx", "adapter_name": "mlx"})
    assert result.outcome == "success"
    assert result.data["scheduled"] is True
    cmd = calls["cmd"]
    assert "install-adapter" in cmd and "chp-adapter-mlx" in cmd
    # adapter_name + discovered profile are passed through to the installer.
    assert "--adapter-name" in cmd and "mlx" in cmd
    assert "--profile" in cmd and "/tmp/inference.json" in cmd
    assert calls["kwargs"].get("start_new_session") is True
    assert calls["kwargs"].get("env", {}).get("HOME")


def test_install_adapter_with_extras(monkeypatch):
    calls: dict = {}
    monkeypatch.setattr(adapter_module.subprocess, "Popen",
                        lambda cmd, **kw: calls.update(cmd=cmd) or type("P", (), {"pid": 1})())
    result = _host().invoke("chp.adapters.host.install_adapter",
                            {"package": "chp-adapter-mlx", "adapter_name": "mlx", "extras": "serve"})
    assert result.outcome == "success"
    cmd = calls["cmd"]
    assert "--extras" in cmd and "serve" in cmd


def test_install_adapter_with_wheel_url(monkeypatch):
    calls: dict = {}
    monkeypatch.setattr(adapter_module.subprocess, "Popen",
                        lambda cmd, **kw: calls.update(cmd=cmd) or type("P", (), {"pid": 1})())
    result = _host().invoke("chp.adapters.host.install_adapter",
                            {"package": "chp-adapter-mlx", "url": "https://example/chp_adapter_mlx-0.8.0.whl"})
    assert result.outcome == "success"
    cmd = calls["cmd"]
    assert "--url" in cmd and "https://example/chp_adapter_mlx-0.8.0.whl" in cmd


def test_install_adapter_requires_package():
    result = _host().invoke("chp.adapters.host.install_adapter", {"package": ""})
    assert result.outcome != "success"


def test_restart_schedules_detached(monkeypatch):
    calls: dict = {}

    class FakeProc:
        pid = 7

    def fake_popen(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(adapter_module.subprocess, "Popen", fake_popen)
    result = _host().invoke("chp.adapters.host.restart", {})
    assert result.outcome == "success"
    assert result.data["scheduled"] is True
    # Spawns `chp-host restart` detached with HOME — no upgrade, no bogus flags.
    assert "restart" in calls["cmd"] and "update" not in calls["cmd"]
    assert calls["kwargs"].get("start_new_session") is True
    assert calls["kwargs"].get("env", {}).get("HOME")


def test_facts_capability():
    result = _host().invoke("chp.adapters.host.facts", {"sections": ["host", "tools"]})
    assert result.outcome == "success"
    d = result.data
    assert "host" in d and "tools" in d
    assert d["host"]["python"]                      # interpreter path always present
    assert isinstance(d["tools"]["git"], dict)      # each tool → {present, [path, version]}
    assert "present" in d["tools"]["git"]


def test_facts_unknown_field_denied():
    result = _host().invoke("chp.adapters.host.facts", {"bogus": 1})
    assert result.outcome == "denied"


def test_topology_capability():
    result = _host().invoke("chp.adapters.host.topology", {})
    assert result.outcome == "success"
    d = result.data
    assert isinstance(d["radicle_peers"], list)
    assert isinstance(d["tailscale_devices"], list)
    assert "radicle_connected" in d and "tailscale_online" in d


def test_inference_capacity_reports_memory_ceiling():
    result = _host().invoke("chp.adapters.host.inference_capacity", {})
    assert result.outcome == "success"
    d = result.data
    assert d["ram_gb"] > 0 and d["gpu_memory_gb"] > 0        # a real memory ceiling
    assert "unified_memory" in d and "gpu_ceiling_source" in d
    assert "fit" not in d                                    # no model → no fit verdict


def test_inference_capacity_fit_verdict():
    # a huge model must NOT fit a tiny ceiling; a tiny model must fit cold
    from chp_adapter_host.adapter import _estimate_fit
    small_node = {"gpu_memory_gb": 8.0, "free_gb": 6.0}
    big = _estimate_fit(small_node, {"params_b": 70, "quant": "q4", "context_tokens": 8192})
    assert big["fits_cold"] is False                         # 70B nowhere near 8GB
    tiny = _estimate_fit(small_node, {"params_b": 1.5, "quant": "q4", "context_tokens": 2048})
    assert tiny["fits_cold"] is True
    assert tiny["estimated_peak_gb"] >= tiny["estimated_steady_gb"]  # peak ≥ steady


def test_inference_capacity_fit_uses_free_memory_now():
    from chp_adapter_host.adapter import _estimate_fit
    # steady fits the ceiling, but current free memory is tiny → fits_now is False (the OOM signal)
    node = {"gpu_memory_gb": 20.0, "free_gb": 3.0}
    f = _estimate_fit(node, {"params_b": 7, "quant": "q4", "context_tokens": 8192})
    assert f["fits_cold"] is True and f["fits_now"] is False
