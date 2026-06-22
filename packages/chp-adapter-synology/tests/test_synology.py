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
# _DSMBackend version negotiation (the code-104 fix) — httpx mock transport
# ---------------------------------------------------------------------------

def _dsm_with_mock(handler):
    import httpx
    from chp_adapter_synology.adapter import _DSMBackend

    backend = _DSMBackend(SynologyConfig(base_url="http://nas:5000", username="u", password="p"))
    backend._sid = "SID"  # skip auth round-trip
    orig_client = backend._client

    def _client():
        return httpx.Client(base_url="http://nas:5000", transport=httpx.MockTransport(handler))

    backend._client = _client  # type: ignore[assignment]
    return backend


def test_resolve_version_clamps_to_max_supported():
    """Container Manager advertises a lower max than we prefer → clamp down (no code 104)."""
    import json as _json
    import httpx

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if "query.cgi" in request.url.path:
            # SYNO.Docker.Container only goes up to v1 on this DSM.
            return httpx.Response(200, json={
                "success": True,
                "data": {"SYNO.Docker.Container": {"minVersion": 1, "maxVersion": 1, "path": "entry.cgi"}},
            })
        seen["version"] = request.url.params.get("version")
        return httpx.Response(200, json={"success": True, "data": {"containers": []}})

    backend = _dsm_with_mock(handler)
    backend.container_list()  # prefers version=2 in code
    assert seen["version"] == "1", "should negotiate down to the max the NAS supports"


def test_resolve_version_falls_back_when_info_unavailable():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if "query.cgi" in request.url.path:
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={"success": True, "data": {"total": 0, "tasks": []}})

    backend = _dsm_with_mock(handler)
    # Should not raise — falls back to the preferred version.
    assert backend.task_list() == {"total": 0, "tasks": []}
