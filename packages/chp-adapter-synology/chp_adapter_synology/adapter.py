"""SynologyAdapter — Synology DSM file ops, tasks, and Container Manager as CHP capabilities.

Auth: DSM session token (SID) acquired via /webapi/auth.cgi; cached in instance;
refreshed on 403. Username/password are NEVER stored in evidence.

Evidence policy: file counts, container IDs, task names are evidenced.
File content and credentials are NEVER in evidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from chp_core import BaseAdapter, capability

_EMITS = ["synology_request", "synology_response", "synology_error"]
_MAX_ERR = 500


# ---------------------------------------------------------------------------
# Injectable backend protocol (for tests)
# ---------------------------------------------------------------------------

class SynologyBackend(Protocol):
    def file_list(self, path: str, limit: int) -> dict[str, Any]: ...
    def file_info(self, path: str) -> dict[str, Any]: ...
    def task_list(self) -> dict[str, Any]: ...
    def container_list(self) -> dict[str, Any]: ...
    def container_start(self, container_id: str) -> dict[str, Any]: ...
    def container_stop(self, container_id: str) -> dict[str, Any]: ...
    def download_create(self, uri: str, dest_folder: str) -> dict[str, Any]: ...


class FakeSynologyBackend:
    """In-memory Synology backend for tests — no live NAS required."""

    def __init__(self) -> None:
        self._files = {
            "/homes": [
                {"name": "document.txt", "path": "/homes/document.txt", "isdir": False, "size": 1024},
                {"name": "photos", "path": "/homes/photos", "isdir": True, "size": 0},
            ]
        }
        self._containers = [
            {"id": "abc123", "name": "plex", "status": "running"},
            {"id": "def456", "name": "homeassistant", "status": "stopped"},
        ]
        self._tasks = [
            {"id": 1, "name": "Daily Backup", "status": "normal", "last_run": "2026-06-12 02:00:00"},
        ]
        self._container_states: dict[str, str] = {"abc123": "running", "def456": "stopped"}

    def file_list(self, path: str, limit: int) -> dict[str, Any]:
        files = self._files.get(path, [])
        return {"total": len(files), "offset": 0, "files": files[:limit]}

    def file_info(self, path: str) -> dict[str, Any]:
        for folder_files in self._files.values():
            for f in folder_files:
                if f["path"] == path:
                    return {**f, "owner": "admin", "modified": "2026-06-01T12:00:00Z"}
        return {"path": path, "exists": False}

    def task_list(self) -> dict[str, Any]:
        return {"total": len(self._tasks), "tasks": list(self._tasks)}

    def container_list(self) -> dict[str, Any]:
        containers = [
            {**c, "status": self._container_states.get(c["id"], c["status"])}
            for c in self._containers
        ]
        return {"total": len(containers), "containers": containers}

    def container_start(self, container_id: str) -> dict[str, Any]:
        if container_id not in self._container_states:
            raise ValueError(f"Container {container_id!r} not found")
        self._container_states[container_id] = "running"
        return {"container_id": container_id, "status": "running"}

    def container_stop(self, container_id: str) -> dict[str, Any]:
        if container_id not in self._container_states:
            raise ValueError(f"Container {container_id!r} not found")
        self._container_states[container_id] = "stopped"
        return {"container_id": container_id, "status": "stopped"}

    def download_create(self, uri: str, dest_folder: str) -> dict[str, Any]:
        return {"task_id": "DL001", "uri": uri, "dest_folder": dest_folder, "status": "queued"}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class SynologyConfig:
    base_url: str = ""
    username: str = ""
    password: str = ""
    allowed_folders: list[str] | None = None
    verify_ssl: bool = True
    backend: SynologyBackend | None = field(default=None, repr=False)

    def resolved_url(self) -> str:
        return self.base_url or os.environ.get("SYNOLOGY_URL", "")

    def resolved_username(self) -> str:
        return self.username or os.environ.get("SYNOLOGY_USER", "")

    def resolved_password(self) -> str:
        return self.password or os.environ.get("SYNOLOGY_PASSWORD", "")


# ---------------------------------------------------------------------------
# Live DSM backend
# ---------------------------------------------------------------------------

class _DSMBackend:
    """Live Synology DSM backend via WebAPI."""

    def __init__(self, config: SynologyConfig) -> None:
        self._config = config
        self._sid: str | None = None

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self._config.resolved_url(), verify=self._config.verify_ssl, timeout=30)

    def _auth(self, client: httpx.Client) -> str:
        params = {
            "api": "SYNO.API.Auth",
            "version": "3",
            "method": "login",
            "account": self._config.resolved_username(),
            "passwd": self._config.resolved_password(),  # never logged by httpx
            "session": "FileStation",
            "format": "sid",
        }
        resp = client.get("/webapi/auth.cgi", params=params)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"DSM auth failed: {data.get('error', {}).get('code', 'unknown')}")
        return str(data["data"]["sid"])

    def _sid_or_auth(self, client: httpx.Client) -> str:
        if not self._sid:
            self._sid = self._auth(client)
        return self._sid

    def _get(self, client: httpx.Client, api: str, method: str, version: int = 1, **extra: Any) -> Any:
        sid = self._sid_or_auth(client)
        params = {"api": api, "version": version, "method": method, "_sid": sid, **extra}
        resp = client.get("/webapi/entry.cgi", params=params)
        if resp.status_code == 403:
            self._sid = self._auth(client)
            params["_sid"] = self._sid
            resp = client.get("/webapi/entry.cgi", params=params)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"DSM API {api}.{method} failed: {data.get('error', {})}")
        return data.get("data", {})

    def _post(self, client: httpx.Client, api: str, method: str, version: int = 1, **extra: Any) -> Any:
        sid = self._sid_or_auth(client)
        payload = {"api": api, "version": version, "method": method, "_sid": sid, **extra}
        resp = client.post("/webapi/entry.cgi", data=payload)
        if resp.status_code == 403:
            self._sid = self._auth(client)
            payload["_sid"] = self._sid
            resp = client.post("/webapi/entry.cgi", data=payload)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"DSM API {api}.{method} failed: {data.get('error', {})}")
        return data.get("data", {})

    def file_list(self, path: str, limit: int) -> dict[str, Any]:
        with self._client() as c:
            return self._get(c, "SYNO.FileStation.List", "list", version=2,
                             folder_path=path, limit=limit,
                             additional="size,time,owner")

    def file_info(self, path: str) -> dict[str, Any]:
        with self._client() as c:
            return self._get(c, "SYNO.FileStation.Info", "getinfo", version=2,
                             path=path, additional="size,time,owner")

    def task_list(self) -> dict[str, Any]:
        with self._client() as c:
            return self._get(c, "SYNO.Core.TaskScheduler", "list", version=3)

    def container_list(self) -> dict[str, Any]:
        with self._client() as c:
            return self._get(c, "SYNO.Docker.Container", "list", version=2)

    def container_start(self, container_id: str) -> dict[str, Any]:
        with self._client() as c:
            return self._post(c, "SYNO.Docker.Container", "start", version=2, id=container_id)

    def container_stop(self, container_id: str) -> dict[str, Any]:
        with self._client() as c:
            return self._post(c, "SYNO.Docker.Container", "stop", version=2, id=container_id)

    def download_create(self, uri: str, dest_folder: str) -> dict[str, Any]:
        with self._client() as c:
            return self._post(c, "SYNO.DownloadStation.Task", "create", version=3,
                              uri=uri, destination=dest_folder)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class SynologyAdapter(BaseAdapter):
    """Synology DSM file operations, task scheduler, and Container Manager as CHP capabilities."""

    adapter_id = "chp.adapters.synology"
    adapter_name = "Synology"
    adapter_description = "Synology DSM file operations, task scheduler, and Container Manager."
    adapter_category = "edge"
    adapter_tags = ["synology", "dsm", "nas", "storage", "edge"]

    def __init__(self, config: SynologyConfig | None = None) -> None:
        self._config = config or SynologyConfig()
        self._live: _DSMBackend | None = None

    def _backend(self) -> SynologyBackend:
        if self._config.backend is not None:
            return self._config.backend
        if not self._config.resolved_url():
            raise RuntimeError(
                "No Synology URL configured. Set SYNOLOGY_URL or pass base_url to SynologyConfig."
            )
        if self._live is None:
            self._live = _DSMBackend(self._config)
        return self._live

    def _check_folder(self, path: str) -> None:
        allowed = self._config.allowed_folders
        if allowed is None:
            return
        if not any(path == f or path.startswith(f.rstrip("/") + "/") for f in allowed):
            raise ValueError(f"Folder {path!r} is not in the allowed list: {allowed}")

    @capability(
        id="chp.adapters.synology.file_list",
        version="1.0.0",
        description="List files in a Synology shared folder.",
        category="edge",
        provider="synology",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    )
    async def file_list(self, ctx: Any, payload: Any) -> Any:
        path: str = payload["path"]
        limit: int = payload.get("limit", 100)
        self._check_folder(path)
        backend = self._backend()
        ctx.emit("synology_request", {"op": "file_list", "path": path, "limit": limit}, redacted=False)
        try:
            result = backend.file_list(path, limit)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "file_list", "path": path, "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {
            "op": "file_list", "path": path, "total": result.get("total", 0),
        }, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.file_info",
        version="1.0.0",
        description="Get metadata (size, modified, owner) for a file or folder.",
        category="edge",
        provider="synology",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "minLength": 1}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )
    async def file_info(self, ctx: Any, payload: Any) -> Any:
        path: str = payload["path"]
        backend = self._backend()
        ctx.emit("synology_request", {"op": "file_info", "path": path}, redacted=False)
        try:
            result = backend.file_info(path)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "file_info", "path": path, "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "file_info", "path": path}, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.task_list",
        version="1.0.0",
        description="List Task Scheduler jobs and their last run status.",
        category="edge",
        provider="synology",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def task_list(self, ctx: Any, payload: Any) -> Any:
        backend = self._backend()
        ctx.emit("synology_request", {"op": "task_list"}, redacted=False)
        try:
            result = backend.task_list()
        except Exception as exc:
            ctx.emit("synology_error", {"op": "task_list", "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "task_list", "total": result.get("total", 0)}, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.container_list",
        version="1.0.0",
        description="List Container Manager containers and their status.",
        category="edge",
        provider="synology",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def container_list(self, ctx: Any, payload: Any) -> Any:
        backend = self._backend()
        ctx.emit("synology_request", {"op": "container_list"}, redacted=False)
        try:
            result = backend.container_list()
        except Exception as exc:
            ctx.emit("synology_error", {"op": "container_list", "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "container_list", "total": result.get("total", 0)}, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.container_start",
        version="1.0.0",
        description="Start a Container Manager container.",
        category="edge",
        provider="synology",
        risk="high",
        side_effects=["container_lifecycle"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"container_id": {"type": "string", "minLength": 1}},
            "required": ["container_id"],
            "additionalProperties": False,
        },
    )
    async def container_start(self, ctx: Any, payload: Any) -> Any:
        container_id: str = payload["container_id"]
        backend = self._backend()
        ctx.emit("synology_request", {"op": "container_start", "container_id": container_id}, redacted=False)
        try:
            result = backend.container_start(container_id)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "container_start", "container_id": container_id, "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "container_start", "container_id": container_id, "status": result.get("status")}, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.container_stop",
        version="1.0.0",
        description="Stop a Container Manager container.",
        category="edge",
        provider="synology",
        risk="high",
        side_effects=["container_lifecycle"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"container_id": {"type": "string", "minLength": 1}},
            "required": ["container_id"],
            "additionalProperties": False,
        },
    )
    async def container_stop(self, ctx: Any, payload: Any) -> Any:
        container_id: str = payload["container_id"]
        backend = self._backend()
        ctx.emit("synology_request", {"op": "container_stop", "container_id": container_id}, redacted=False)
        try:
            result = backend.container_stop(container_id)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "container_stop", "container_id": container_id, "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "container_stop", "container_id": container_id, "status": result.get("status")}, redacted=False)
        return result

    @capability(
        id="chp.adapters.synology.download_create",
        version="1.0.0",
        description="Add a download task to Download Station.",
        category="edge",
        provider="synology",
        risk="medium",
        side_effects=["network_download"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "uri": {"type": "string", "minLength": 1},
                "dest_folder": {"type": "string", "minLength": 1},
            },
            "required": ["uri", "dest_folder"],
            "additionalProperties": False,
        },
    )
    async def download_create(self, ctx: Any, payload: Any) -> Any:
        uri: str = payload["uri"]
        dest_folder: str = payload["dest_folder"]
        self._check_folder(dest_folder)
        backend = self._backend()
        ctx.emit("synology_request", {"op": "download_create", "dest_folder": dest_folder}, redacted=False)
        try:
            result = backend.download_create(uri, dest_folder)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "download_create", "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "download_create", "task_id": result.get("task_id")}, redacted=False)
        return result
