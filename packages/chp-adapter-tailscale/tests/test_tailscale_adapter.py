"""Tests for chp_adapter_tailscale.

FakeCtx intercepts ctx.ainvoke() and returns scripted HTTP responses
matching the Tailscale HTTP API v2 shape. No live Tailscale account needed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from chp_adapter_tailscale import TailscaleAdapter, TailscaleConfig


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeResult:
    success: bool
    data: Any = None
    error: Any = None


class FakeCtx:
    def __init__(self, responses: list[FakeResult] | None = None) -> None:
        self._queue: list[FakeResult] = list(responses or [])
        self.emitted: list[tuple[str, dict]] = []
        self.invoked: list[tuple[str, dict]] = []

    def emit(self, event_type: str, payload: dict, redacted: bool = False) -> None:
        self.emitted.append((event_type, payload))

    async def ainvoke(self, cap_id: str, payload: dict, **_kw) -> FakeResult:
        self.invoked.append((cap_id, payload))
        if self._queue:
            return self._queue.pop(0)
        return FakeResult(success=True, data={"status_code": 200, "json": {}})


def _ts_resp(devices: list[dict]) -> FakeResult:
    return FakeResult(success=True, data={"status_code": 200, "json": {"devices": devices}})


def _health_ok(status: int = 200) -> FakeResult:
    return FakeResult(success=True, data={"status_code": status, "json": {"ok": True}})


def _health_fail() -> FakeResult:
    return FakeResult(success=False, error="connection refused")


def _make_device(
    hostname: str = "mac-primary",
    ts_ip: str = "100.1.2.3",
    fqdn: str = "mac-primary.tail1234.ts.net",
    os: str = "macOS",
    tags: list[str] | None = None,
    last_seen: str = "2026-06-18T10:00:00Z",
    blocks: bool = False,
) -> dict:
    return {
        "id": hostname,
        "hostname": hostname,
        "name": fqdn,
        "os": os,
        "tags": tags or [],
        "addresses": [ts_ip, "fd7a::1"],
        "lastSeen": last_seen,
        "blocksIncomingConnections": blocks,
    }


def _cfg(**kw) -> TailscaleConfig:
    base = dict(api_key="ts-test-key", tailnet="test@example.com")
    base.update(kw)
    return TailscaleConfig(**base)


# ---------------------------------------------------------------------------
# 1. Shaping
# ---------------------------------------------------------------------------

class TestShaping:
    def test_three_capabilities(self):
        ids = {c.descriptor.id for c in TailscaleAdapter().capabilities()}
        assert ids == {
            "chp.adapters.tailscale.devices",
            "chp.adapters.tailscale.chp_hosts",
            "chp.adapters.tailscale.verify_mesh",
        }

    def test_adapter_id(self):
        assert TailscaleAdapter().adapter_id == "chp.adapters.tailscale"

    def test_devices_low_risk(self):
        cap = {c.descriptor.id: c.descriptor for c in TailscaleAdapter().capabilities()}
        assert cap["chp.adapters.tailscale.devices"].risk == "low"

    def test_verify_mesh_low_risk(self):
        cap = {c.descriptor.id: c.descriptor for c in TailscaleAdapter().capabilities()}
        assert cap["chp.adapters.tailscale.verify_mesh"].risk == "low"

    def test_default_port_8803(self):
        assert TailscaleConfig().default_chp_port == 8803

    def test_nas_tag_maps_to_8802(self):
        assert TailscaleConfig().port_for(["tag:chp-nas"]) == 8802

    def test_raspi_tag_maps_to_8801(self):
        assert TailscaleConfig().port_for(["tag:chp-raspi"]) == 8801

    def test_unknown_tags_use_default(self):
        assert TailscaleConfig().port_for(["tag:something-else"]) == 8803

    def test_no_api_key_raises(self):
        ctx = FakeCtx()
        adapter = TailscaleAdapter(TailscaleConfig(tailnet="me"))
        with pytest.raises(RuntimeError, match="API key"):
            asyncio.run(adapter.devices(ctx, {}))


# ---------------------------------------------------------------------------
# 2. devices
# ---------------------------------------------------------------------------

class TestDevices:
    def _run(self, ctx, devices, **kw):
        adapter = TailscaleAdapter(_cfg())
        return asyncio.run(adapter.devices(ctx, kw))

    def test_returns_device_list(self):
        ctx = FakeCtx([_ts_resp([_make_device()])])
        result = self._run(ctx, [])
        assert result["device_count"] == 1
        assert result["devices"][0]["hostname"] == "mac-primary"

    def test_emits_devices_listed(self):
        ctx = FakeCtx([_ts_resp([_make_device()])])
        self._run(ctx, [])
        types = [e[0] for e in ctx.emitted]
        assert "tailscale_devices_listed" in types

    def test_event_has_tailnet_and_counts(self):
        ctx = FakeCtx([_ts_resp([_make_device(), _make_device("mac-2", "100.1.2.4")])])
        self._run(ctx, [])
        ev = next(e[1] for e in ctx.emitted if e[0] == "tailscale_devices_listed")
        assert ev["device_count"] == 2
        assert ev["tailnet"] == "test@example.com"

    def test_normalises_tailscale_ip(self):
        ctx = FakeCtx([_ts_resp([_make_device(ts_ip="100.99.1.2")])])
        result = self._run(ctx, [])
        assert result["devices"][0]["tailscale_ip"] == "100.99.1.2"

    def test_normalises_online_status(self):
        ctx = FakeCtx([_ts_resp([_make_device(blocks=False), _make_device("offline", "100.1.2.9", blocks=True)])])
        result = self._run(ctx, [])
        online = [d["online"] for d in result["devices"]]
        assert online == [True, False]

    def test_exclude_offline_when_requested(self):
        ctx = FakeCtx([_ts_resp([_make_device(), _make_device("offline", "100.1.2.9", blocks=True)])])
        result = self._run(ctx, [], include_offline=False)
        assert result["device_count"] == 1
        assert result["devices"][0]["hostname"] == "mac-primary"

    def test_online_count_in_result(self):
        ctx = FakeCtx([_ts_resp([_make_device(), _make_device("offline", blocks=True)])])
        result = self._run(ctx, [])
        assert result["online_count"] == 1

    def test_routes_through_http_cap(self):
        ctx = FakeCtx([_ts_resp([])])
        self._run(ctx, [])
        assert all(inv[0] == "chp.adapters.http.request" for inv in ctx.invoked)

    def test_calls_tailscale_api_url(self):
        ctx = FakeCtx([_ts_resp([])])
        self._run(ctx, [])
        url = ctx.invoked[0][1]["url"]
        assert "api.tailscale.com/api/v2/tailnet" in url

    def test_http_error_emits_tailscale_error(self):
        ctx = FakeCtx([FakeResult(success=False, error="timeout")])
        with pytest.raises(RuntimeError):
            self._run(ctx, [])
        types = [e[0] for e in ctx.emitted]
        assert "tailscale_error" in types

    def test_api_400_raises(self):
        ctx = FakeCtx([FakeResult(success=True, data={"status_code": 401, "json": {"message": "Unauthorized"}})])
        with pytest.raises(RuntimeError):
            self._run(ctx, [])


# ---------------------------------------------------------------------------
# 3. chp_hosts
# ---------------------------------------------------------------------------

class TestChpHosts:
    def _run(self, ctx, **kw):
        adapter = TailscaleAdapter(_cfg())
        return asyncio.run(adapter.chp_hosts(ctx, kw))

    def _run_with_cfg(self, ctx, cfg, **kw):
        adapter = TailscaleAdapter(cfg)
        return asyncio.run(adapter.chp_hosts(ctx, kw))

    def test_returns_hosts_with_chp_url(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])])])
        result = self._run(ctx)
        assert result["host_count"] == 1
        assert result["hosts"][0]["chp_url"] == "http://100.1.2.3:8803"

    def test_emits_chp_hosts_resolved(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])])])
        self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "tailscale_chp_hosts_resolved" in types

    def test_nas_tag_assigns_port_8802(self):
        ctx = FakeCtx([_ts_resp([_make_device(hostname="nas", ts_ip="100.2.3.4", tags=["tag:chp-host", "tag:chp-nas"])])])
        result = self._run(ctx)
        assert result["hosts"][0]["chp_port"] == 8802
        assert ":8802" in result["hosts"][0]["chp_url"]

    def test_raspi_tag_assigns_port_8801(self):
        ctx = FakeCtx([_ts_resp([_make_device(hostname="rpi", ts_ip="100.3.4.5", tags=["tag:chp-host", "tag:chp-raspi"])])])
        result = self._run(ctx)
        assert result["hosts"][0]["chp_port"] == 8801

    def test_role_nas(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host", "tag:chp-nas"])])])
        result = self._run(ctx)
        assert result["hosts"][0]["role"] == "nas"

    def test_role_raspi(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host", "tag:chp-raspi"])])])
        result = self._run(ctx)
        assert result["hosts"][0]["role"] == "raspi"

    def test_role_worker_default(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])])])
        result = self._run(ctx)
        assert result["hosts"][0]["role"] == "worker"

    def test_devices_without_chp_host_tag_excluded(self):
        ctx = FakeCtx([_ts_resp([
            _make_device("mac", "100.1.1.1", tags=["tag:chp-host"]),
            _make_device("other", "100.1.1.2", tags=[]),  # no chp-host tag
        ])])
        result = self._run(ctx)
        assert result["host_count"] == 1
        assert result["hosts"][0]["hostname"] == "mac"

    def test_no_filter_tag_includes_all(self):
        cfg = _cfg(chp_host_tag="")
        ctx = FakeCtx([_ts_resp([
            _make_device("a", "100.1.1.1", tags=[]),
            _make_device("b", "100.1.1.2", tags=[]),
        ])])
        result = self._run_with_cfg(ctx, cfg)
        assert result["host_count"] == 2

    def test_offline_excluded_by_default(self):
        ctx = FakeCtx([_ts_resp([
            _make_device("online", "100.1.1.1", tags=["tag:chp-host"], blocks=False),
            _make_device("offline", "100.1.1.2", tags=["tag:chp-host"], blocks=True),
        ])])
        result = self._run(ctx)
        assert result["host_count"] == 1
        assert result["hosts"][0]["hostname"] == "online"

    def test_magicDNS_option_uses_fqdn(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"], fqdn="mac.tail1234.ts.net")])])
        result = self._run(ctx, use_magicDNS=True)
        assert "mac.tail1234.ts.net" in result["hosts"][0]["chp_url"]

    def test_latency_ms_present(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])])])
        result = self._run(ctx)
        assert isinstance(result["latency_ms"], int)


# ---------------------------------------------------------------------------
# 4. verify_mesh
# ---------------------------------------------------------------------------

class TestVerifyMesh:
    def _run(self, ctx, **kw):
        adapter = TailscaleAdapter(_cfg())
        return asyncio.run(adapter.verify_mesh(ctx, kw))

    def test_healthy_host_ok(self):
        ctx = FakeCtx([
            _ts_resp([_make_device(tags=["tag:chp-host"])]),
            _health_ok(),
        ])
        result = self._run(ctx)
        assert result["hosts_ok"] == 1
        assert result["hosts_failed"] == 0
        assert result["results"][0]["ok"] is True

    def test_unreachable_host_fails(self):
        ctx = FakeCtx([
            _ts_resp([_make_device(tags=["tag:chp-host"])]),
            _health_fail(),
        ])
        result = self._run(ctx)
        assert result["hosts_ok"] == 0
        assert result["hosts_failed"] == 1
        assert result["results"][0]["ok"] is False

    def test_mixed_results(self):
        ctx = FakeCtx([
            _ts_resp([
                _make_device("mac", "100.1.1.1", tags=["tag:chp-host"]),
                _make_device("nas", "100.1.1.2", tags=["tag:chp-host", "tag:chp-nas"]),
            ]),
            _health_ok(),
            _health_fail(),
        ])
        result = self._run(ctx)
        assert result["hosts_ok"] == 1
        assert result["hosts_failed"] == 1

    def test_emits_mesh_verified(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])]), _health_ok()])
        self._run(ctx)
        types = [e[0] for e in ctx.emitted]
        assert "tailscale_mesh_verified" in types

    def test_event_counts(self):
        ctx = FakeCtx([
            _ts_resp([_make_device("a", "100.1.1.1", tags=["tag:chp-host"]),
                      _make_device("b", "100.1.1.2", tags=["tag:chp-host"])]),
            _health_ok(), _health_ok(),
        ])
        self._run(ctx)
        ev = next(e[1] for e in ctx.emitted if e[0] == "tailscale_mesh_verified")
        assert ev["hosts_checked"] == 2
        assert ev["hosts_ok"] == 2

    def test_probe_url_uses_tailscale_ip(self):
        ctx = FakeCtx([
            _ts_resp([_make_device(ts_ip="100.99.0.1", tags=["tag:chp-host"])]),
            _health_ok(),
        ])
        self._run(ctx)
        # Second invocation is the health probe
        probe_url = ctx.invoked[1][1]["url"]
        assert "100.99.0.1" in probe_url
        assert "/health" in probe_url

    def test_nas_probe_uses_port_8802(self):
        ctx = FakeCtx([
            _ts_resp([_make_device("nas", "100.2.2.2", tags=["tag:chp-host", "tag:chp-nas"])]),
            _health_ok(),
        ])
        self._run(ctx)
        probe_url = ctx.invoked[1][1]["url"]
        assert ":8802/health" in probe_url

    def test_empty_tailnet_returns_zero(self):
        ctx = FakeCtx([_ts_resp([])])
        result = self._run(ctx)
        assert result["hosts_checked"] == 0
        assert result["results"] == []

    def test_status_code_recorded(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])]), _health_ok(200)])
        result = self._run(ctx)
        assert result["results"][0]["status_code"] == 200

    def test_probe_ms_present(self):
        ctx = FakeCtx([_ts_resp([_make_device(tags=["tag:chp-host"])]), _health_ok()])
        result = self._run(ctx)
        assert isinstance(result["results"][0]["probe_ms"], int)


# ---------------------------------------------------------------------------
# 5. Config resolution
# ---------------------------------------------------------------------------

class TestConfig:
    def test_env_api_key(self, monkeypatch):
        monkeypatch.setenv("TAILSCALE_API_KEY", "ts-env-key")
        assert TailscaleConfig().resolved_api_key() == "ts-env-key"

    def test_explicit_api_key_wins(self, monkeypatch):
        monkeypatch.setenv("TAILSCALE_API_KEY", "ts-env-key")
        assert TailscaleConfig(api_key="ts-explicit").resolved_api_key() == "ts-explicit"

    def test_env_tailnet(self, monkeypatch):
        monkeypatch.setenv("TAILSCALE_TAILNET", "user@corp.com")
        assert TailscaleConfig().resolved_tailnet() == "user@corp.com"

    def test_default_tailnet_is_me(self):
        assert TailscaleConfig().resolved_tailnet() == "me"

    def test_custom_port_by_tag(self):
        cfg = TailscaleConfig(port_by_tag={"tag:custom": 9000})
        assert cfg.port_for(["tag:custom"]) == 9000
