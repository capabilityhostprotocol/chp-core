"""Tests for chp-adapter-launchd using a fake backend — no launchctl calls."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from chp_adapter_http import HttpAdapter, HttpConfig
from chp_adapter_launchd import LaunchdAdapter, LaunchdConfig
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore


class FakeLaunchdBackend:
    def __init__(self) -> None:
        self.installed: dict[str, dict] = {}

    def list_services(self, prefix: str) -> list[dict]:
        return [
            {"label": "com.chp.tei", "pid": 4242, "running": True, "last_exit_code": 0},
            {"label": "com.chp.vllm", "pid": None, "running": False, "last_exit_code": 1},
        ]

    def status(self, label: str) -> dict:
        return {"label": label, "loaded": True, "running": True, "pid": 4242,
                "last_exit_code": 0, "plist_exists": True}

    def start(self, label: str, plist_path: str | None) -> dict:
        return {"label": label, "action": "bootstrap", "ok": True, "returncode": 0, "stderr": ""}

    def stop(self, label: str) -> dict:
        return {"label": label, "action": "bootout", "ok": True, "returncode": 0, "stderr": ""}

    def install(self, label: str, spec: dict) -> dict:
        self.installed[label] = spec
        return {"label": label, "plist_path": f"/fake/LaunchAgents/{label}.plist", "ok": True,
                "returncode": 0, "stderr": "", "env_keys": sorted((spec.get("env") or {}).keys())}

    def uninstall(self, label: str) -> dict:
        return {"label": label, "booted_out": True, "plist_removed": True,
                "plist_path": f"/fake/LaunchAgents/{label}.plist"}


def _make_host(
    fake: FakeLaunchdBackend | None = None,
    transport: Any = None,
    model_probes: list[dict] | None = None,
) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    cfg = LaunchdConfig(_backend=fake or FakeLaunchdBackend())
    if model_probes is not None:
        cfg.model_probes = model_probes
    if transport is not None:
        register_adapter(host, HttpAdapter(HttpConfig(transport=transport, max_retries=0, backoff_base=0.0)))
    register_adapter(host, LaunchdAdapter(cfg))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


class TestList:
    def test_returns_services(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.list", {})
        assert result.success
        assert result.data["service_count"] == 2
        assert result.data["services"][0]["label"] == "com.chp.tei"


class TestStatus:
    def test_returns_status(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.status", {"label": "com.chp.tei"})
        assert result.success
        assert result.data["running"] is True
        assert result.data["pid"] == 4242

    def test_unmanaged_label_rejected(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.status", {"label": "com.apple.something"})
        assert not result.success


class TestStartStop:
    def test_start(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.start", {"label": "com.chp.tei"})
        assert result.success
        assert result.data["ok"] is True

    def test_stop(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.stop", {"label": "com.chp.vllm"})
        assert result.success
        assert result.data["action"] == "bootout"

    def test_start_unmanaged_rejected(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.start", {"label": "org.other.svc"})
        assert not result.success


class TestInstall:
    def test_install_writes_spec(self):
        fake = FakeLaunchdBackend()
        result = _invoke(_make_host(fake), "chp.adapters.launchd.install", {
            "label": "com.chp.tei",
            "program": "/opt/homebrew/bin/text-embeddings-router",
            "args": ["--model-id", "x", "--port", "8090"],
        })
        assert result.success
        assert result.data["ok"] is True
        assert "com.chp.tei" in fake.installed
        assert fake.installed["com.chp.tei"]["program"].endswith("text-embeddings-router")

    def test_env_values_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.launchd.install", {
            "label": "com.chp.secretsvc",
            "program": "/bin/echo",
            "env": {"API_KEY": "SUPER_SECRET_VALUE_123"},
        })
        assert result.success
        # env_keys present, value absent
        assert result.data["env_keys"] == ["API_KEY"]
        replay = host.replay(result.invocation_id)
        for evt in replay:
            blob = str(evt.get("payload", {}))
            assert "SUPER_SECRET_VALUE_123" not in blob

    def test_install_unmanaged_rejected(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.install", {
            "label": "com.apple.evil", "program": "/bin/sh",
        })
        assert not result.success


class TestUninstall:
    def test_uninstall(self):
        result = _invoke(_make_host(), "chp.adapters.launchd.uninstall", {"label": "com.chp.tei"})
        assert result.success
        assert result.data["plist_removed"] is True


class TestServiceHealth:
    def _mock_transport(self, tei_up: bool = True, vllm_up: bool = True) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "8090" in url:
                return httpx.Response(200 if tei_up else 503, json={"status": "ok"})
            if "8092" in url:
                return httpx.Response(200 if vllm_up else 503, json={"data": []})
            return httpx.Response(404)
        return httpx.MockTransport(handler)

    def test_service_health_all_up(self):
        probes = [
            {"name": "tei", "url": "http://localhost:8090/health", "expect_status": 200},
            {"name": "vllm", "url": "http://localhost:8092/v1/models", "expect_status": 200},
        ]
        host = _make_host(transport=self._mock_transport(True, True), model_probes=probes)
        result = _invoke(host, "chp.adapters.launchd.service_health", {})
        assert result.success
        assert len(result.data["services"]) == 2
        servers = {s["name"]: s for s in result.data["model_servers"]}
        assert servers["tei"]["reachable"] is True
        assert servers["vllm"]["reachable"] is True

    def test_service_health_model_down(self):
        probes = [
            {"name": "tei", "url": "http://localhost:8090/health", "expect_status": 200},
        ]
        host = _make_host(transport=self._mock_transport(tei_up=False), model_probes=probes)
        result = _invoke(host, "chp.adapters.launchd.service_health", {})
        assert result.success
        servers = {s["name"]: s for s in result.data["model_servers"]}
        assert servers["tei"]["reachable"] is False
        assert result.data["ok"] is False

    def test_service_health_no_model_probes(self):
        host = _make_host(model_probes=[])
        result = _invoke(host, "chp.adapters.launchd.service_health", {})
        assert result.success
        assert result.data["model_servers"] == []


class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_launchd.adapter as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"LaunchdAdapter has conformance violations: {violations}"
