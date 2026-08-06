"""Tests for chp-adapter-synology using FakeSynologyBackend — no live NAS required."""

from __future__ import annotations

import pytest

from chp_adapter_synology import SynologyAdapter, SynologyConfig
from chp_adapter_synology.adapter import FakeSynologyBackend
from chp_core import LocalCapabilityHost, register_adapter


def _host_with_fake(allowed_folders=None) -> tuple[LocalCapabilityHost, FakeSynologyBackend]:
    fake = FakeSynologyBackend()
    config = SynologyConfig(backend=fake, allowed_folders=allowed_folders)
    adapter = SynologyAdapter(config)
    host = LocalCapabilityHost()
    register_adapter(host, adapter)
    return host, fake


# ---------------------------------------------------------------------------
# file_list
# ---------------------------------------------------------------------------

def test_file_list_returns_files():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes"})
    assert result.success
    data = result.data
    assert data["total"] == 2
    names = [f["name"] for f in data["files"]]
    assert "document.txt" in names


def test_file_list_limit():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes", "limit": 1})
    assert result.success
    assert len(result.data["files"]) == 1


def test_file_list_empty_path():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/nonexistent"})
    assert result.success
    assert result.data["total"] == 0


def test_file_list_allowed_folders_blocks():
    host, fake = _host_with_fake(allowed_folders=["/restricted"])
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes"})
    assert not result.success


def test_file_list_allowed_folders_passes():
    host, fake = _host_with_fake(allowed_folders=["/homes"])
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes"})
    assert result.success


def test_file_list_allowed_subpath():
    host, fake = _host_with_fake(allowed_folders=["/homes"])
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes/subdir"})
    assert result.success


# ---------------------------------------------------------------------------
# file_info
# ---------------------------------------------------------------------------

def test_file_info_known_file():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.file_info", {"path": "/homes/document.txt"})
    assert result.success
    assert result.data["name"] == "document.txt"
    assert result.data["owner"] == "admin"


def test_file_info_unknown_file():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.file_info", {"path": "/homes/missing.txt"})
    assert result.success
    assert result.data.get("exists") is False


# ---------------------------------------------------------------------------
# task_list
# ---------------------------------------------------------------------------

def test_task_list_returns_tasks():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.task_list", {})
    assert result.success
    assert result.data["total"] == 1
    assert result.data["tasks"][0]["name"] == "Daily Backup"


# ---------------------------------------------------------------------------
# container_list
# ---------------------------------------------------------------------------

def test_container_list_returns_containers():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.container_list", {})
    assert result.success
    assert result.data["total"] == 2
    names = [c["name"] for c in result.data["containers"]]
    assert "plex" in names


# ---------------------------------------------------------------------------
# container_start / container_stop
# ---------------------------------------------------------------------------

def test_container_start():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.container_start", {"container_id": "def456"})
    assert result.success
    assert result.data["status"] == "running"
    assert fake._container_states["def456"] == "running"


def test_container_stop():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.container_stop", {"container_id": "abc123"})
    assert result.success
    assert result.data["status"] == "stopped"
    assert fake._container_states["abc123"] == "stopped"


def test_container_start_stop_roundtrip():
    host, fake = _host_with_fake()
    host.invoke("chp.adapters.synology.container_stop", {"container_id": "abc123"})
    result = host.invoke("chp.adapters.synology.container_start", {"container_id": "abc123"})
    assert result.success
    assert fake._container_states["abc123"] == "running"


def test_container_start_unknown_id():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.container_start", {"container_id": "zzz999"})
    assert not result.success


# ---------------------------------------------------------------------------
# download_create
# ---------------------------------------------------------------------------

def test_download_create():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.synology.download_create", {
        "uri": "https://example.com/file.zip",
        "dest_folder": "/homes/downloads",
    })
    assert result.success
    assert result.data["task_id"] == "DL001"
    assert result.data["status"] == "queued"


def test_download_create_allowed_folder_blocks():
    host, fake = _host_with_fake(allowed_folders=["/restricted"])
    result = host.invoke("chp.adapters.synology.download_create", {
        "uri": "https://example.com/file.zip",
        "dest_folder": "/homes/downloads",
    })
    assert not result.success


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def test_evidence_recorded_for_all_ops():
    host, fake = _host_with_fake()
    ops = [
        ("chp.adapters.synology.file_list", {"path": "/homes"}),
        ("chp.adapters.synology.task_list", {}),
        ("chp.adapters.synology.container_list", {}),
    ]
    for cap_id, payload in ops:
        result = host.invoke(cap_id, payload)
        assert result.success, f"{cap_id} failed: {result.error}"
        assert result.evidence_ids, f"No evidence for {cap_id}"


# ---------------------------------------------------------------------------
# _DSMBackend version negotiation (the code-104 fix) — fake http-adapter ctx
# ---------------------------------------------------------------------------
#
# The live backend composes through chp.adapters.http via ctx.ainvoke, so we mock
# the http adapter (not a raw client): a fake ctx whose ainvoke routes the request
# dict to a handler returning (status_code, json) — exactly the {status_code, json}
# shape chp.adapters.http.request returns in result.data.

import asyncio


class _FakeResult:
    def __init__(self, data: dict) -> None:
        self.success = True
        self.data = data
        self.error = None


class _FakeHttpCtx:
    """Stands in for the capability ctx: ainvoke(http_cap, req) -> result.data."""

    def __init__(self, handler) -> None:
        self._handler = handler

    async def ainvoke(self, cap: str, req: dict):
        status, js = self._handler(req)
        return _FakeResult({"status_code": status, "json": js})


def _dsm_with_handler(handler):
    from chp_adapter_synology.adapter import _DSMBackend

    backend = _DSMBackend(SynologyConfig(base_url="http://nas:5000", username="u", password="p"))
    backend._sid = "SID"  # skip auth round-trip
    return backend, _FakeHttpCtx(handler)


def test_resolve_version_clamps_to_max_supported():
    """Container Manager advertises a lower max than we prefer → clamp down (no code 104)."""
    seen: dict = {}

    def handler(req: dict):
        url = req["url"]
        params = req.get("params") or {}
        if "query.cgi" in url:
            # SYNO.Docker.Container only goes up to v1 on this DSM.
            return 200, {
                "success": True,
                "data": {"SYNO.Docker.Container": {"minVersion": 1, "maxVersion": 1, "path": "entry.cgi"}},
            }
        seen["version"] = params.get("version")
        return 200, {"success": True, "data": {"containers": []}}

    backend, ctx = _dsm_with_handler(handler)
    asyncio.run(backend.container_list(ctx))  # prefers version=2 in code
    assert seen["version"] == "1", "should negotiate down to the max the NAS supports"


def test_resolve_version_falls_back_when_info_unavailable():
    def handler(req: dict):
        if "query.cgi" in req["url"]:
            return 500, None  # info endpoint down / non-JSON
        return 200, {"success": True, "data": {"total": 0, "tasks": []}}

    backend, ctx = _dsm_with_handler(handler)
    # Should not raise — falls back to the preferred version.
    assert asyncio.run(backend.task_list(ctx)) == {"total": 0, "tasks": []}


def test_reauth_on_dsm_119_stale_sid():
    """A stale SID comes back as HTTP 200 + DSM code 119; _entry must re-auth + retry, not fail."""
    calls = {"entry": 0, "auth": 0}

    def handler(req: dict):
        url = req["url"]
        if "auth.cgi" in url:
            calls["auth"] += 1
            return 200, {"success": True, "data": {"sid": "NEWSID"}}
        if "query.cgi" in url:  # version negotiation
            return 200, {"success": True, "data": {}}
        calls["entry"] += 1  # entry.cgi
        if calls["entry"] == 1:
            return 200, {"success": False, "error": {"code": 119}}  # stale SID
        return 200, {"success": True, "data": {"tasks": []}}

    backend, ctx = _dsm_with_handler(handler)
    assert asyncio.run(backend.task_list(ctx)) == {"tasks": []}
    assert calls["auth"] == 1 and calls["entry"] == 2  # re-authed once, retried once


# --- added DSM health / backup / snapshot / container-log caps ---

def test_storage_volume_list():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.storage_volume_list", {})
    assert r.data["volumes"][0]["raid_type"] == "raid1"


def test_disk_smart_health():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.disk_smart_health", {})
    assert all(d["smart_status"] == "normal" for d in r.data["disks"])


def test_system_info():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.system_info", {})
    assert r.data["model"] == "DS918+"


def test_backup_task_list_and_run():
    host, _ = _host_with_fake()
    assert host.invoke("chp.adapters.synology.backup_task_list", {}).data["tasks"]
    r = host.invoke("chp.adapters.synology.backup_task_run", {"task_id": 1})
    assert r.data["started"] is True


def test_snapshot_create():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.snapshot_create", {"share": "photos", "desc": "pre-op"})
    assert r.data["share"] == "photos" and r.data["desc"] == "pre-op"


def test_container_logs():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.container_logs", {"container_id": "abc123", "lines": 2})
    assert len(r.data["lines"]) == 2


def test_download_task_control():
    host, _ = _host_with_fake()
    r = host.invoke("chp.adapters.synology.download_task_control",
                    {"task_id": "DL001", "action": "pause"})
    assert r.data["action"] == "pause" and r.data["ok"] is True
