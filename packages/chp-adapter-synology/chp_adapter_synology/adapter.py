"""SynologyAdapter — Synology DSM file ops, tasks, and Container Manager as CHP capabilities.

Auth: DSM session token (SID) acquired via /webapi/auth.cgi; cached in instance;
refreshed on 403. Username/password are NEVER stored in evidence.

Transport: all DSM WebAPI calls compose through ``chp.adapters.http`` (the sanctioned
transport) via ``ctx.ainvoke`` — no direct HTTP client. The http adapter evidences only
the bare URL + param *keys* (never values), so credentials passed as params stay out of
evidence; request bodies are not evidenced.

Evidence policy: file counts, container IDs, task names are evidenced.
File content and credentials are NEVER in evidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

from chp_core import BaseAdapter, capability

_EMITS = ["synology_request", "synology_response", "synology_error"]
_MAX_ERR = 500
_HTTP_CAP = "chp.adapters.http.request"


# ---------------------------------------------------------------------------
# Injectable backend protocol (for tests)
# ---------------------------------------------------------------------------

class SynologyBackend(Protocol):
    async def file_list(self, ctx: Any, path: str, limit: int) -> dict[str, Any]: ...
    async def file_info(self, ctx: Any, path: str) -> dict[str, Any]: ...
    async def task_list(self, ctx: Any) -> dict[str, Any]: ...
    async def container_list(self, ctx: Any) -> dict[str, Any]: ...
    async def container_start(self, ctx: Any, container_id: str) -> dict[str, Any]: ...
    async def container_stop(self, ctx: Any, container_id: str) -> dict[str, Any]: ...
    async def download_create(self, ctx: Any, uri: str, dest_folder: str) -> dict[str, Any]: ...
    async def storage_volume_list(self, ctx: Any) -> dict[str, Any]: ...
    async def disk_smart_health(self, ctx: Any) -> dict[str, Any]: ...
    async def system_info(self, ctx: Any) -> dict[str, Any]: ...
    async def system_utilization(self, ctx: Any) -> dict[str, Any]: ...
    async def backup_task_list(self, ctx: Any) -> dict[str, Any]: ...
    async def backup_task_run(self, ctx: Any, task_id: int) -> dict[str, Any]: ...
    async def snapshot_create(self, ctx: Any, share: str, desc: str) -> dict[str, Any]: ...
    async def container_logs(self, ctx: Any, container_id: str, lines: int) -> dict[str, Any]: ...
    async def package_list(self, ctx: Any) -> dict[str, Any]: ...
    async def download_task_control(self, ctx: Any, task_id: str, action: str) -> dict[str, Any]: ...


class FakeSynologyBackend:
    """In-memory Synology backend for tests — no live NAS required.

    Methods are async + ctx-first to match the live backend's signature (which
    composes through chp.adapters.http); ctx is unused here."""

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

    async def file_list(self, ctx: Any, path: str, limit: int) -> dict[str, Any]:
        files = self._files.get(path, [])
        return {"total": len(files), "offset": 0, "files": files[:limit]}

    async def file_info(self, ctx: Any, path: str) -> dict[str, Any]:
        for folder_files in self._files.values():
            for f in folder_files:
                if f["path"] == path:
                    return {**f, "owner": "admin", "modified": "2026-06-01T12:00:00Z"}
        return {"path": path, "exists": False}

    async def task_list(self, ctx: Any) -> dict[str, Any]:
        return {"total": len(self._tasks), "tasks": list(self._tasks)}

    async def container_list(self, ctx: Any) -> dict[str, Any]:
        containers = [
            {**c, "status": self._container_states.get(c["id"], c["status"])}
            for c in self._containers
        ]
        return {"total": len(containers), "containers": containers}

    async def container_start(self, ctx: Any, container_id: str) -> dict[str, Any]:
        if container_id not in self._container_states:
            raise ValueError(f"Container {container_id!r} not found")
        self._container_states[container_id] = "running"
        return {"container_id": container_id, "status": "running"}

    async def container_stop(self, ctx: Any, container_id: str) -> dict[str, Any]:
        if container_id not in self._container_states:
            raise ValueError(f"Container {container_id!r} not found")
        self._container_states[container_id] = "stopped"
        return {"container_id": container_id, "status": "stopped"}

    async def download_create(self, ctx: Any, uri: str, dest_folder: str) -> dict[str, Any]:
        return {"task_id": "DL001", "uri": uri, "dest_folder": dest_folder, "status": "queued"}

    async def storage_volume_list(self, ctx: Any) -> dict[str, Any]:
        return {"volumes": [{"id": "volume_1", "status": "normal", "fs_type": "btrfs",
                             "size_total": 8_000_000_000_000, "size_used": 4_200_000_000_000,
                             "raid_type": "raid1"}]}

    async def disk_smart_health(self, ctx: Any) -> dict[str, Any]:
        return {"disks": [{"id": "sata1", "model": "WD80EFAX", "status": "normal",
                          "smart_status": "normal", "temp": 38},
                         {"id": "sata2", "model": "WD80EFAX", "status": "normal",
                          "smart_status": "normal", "temp": 37}]}

    async def system_info(self, ctx: Any) -> dict[str, Any]:
        return {"model": "DS918+", "firmware_ver": "DSM 7.3.2", "serial": "REDACTED",
                "uptime": 864000, "cpu_series": "Intel Celeron J3455"}

    async def system_utilization(self, ctx: Any) -> dict[str, Any]:
        return {"cpu": {"user_load": 5, "system_load": 3}, "memory": {"real_usage": 42},
                "disk": {"read_byte": 120000, "write_byte": 80000}}

    async def backup_task_list(self, ctx: Any) -> dict[str, Any]:
        return {"tasks": [{"task_id": 1, "name": "Offsite", "status": "backupable",
                          "last_bkp_result": "success", "last_bkp_time": "2026-07-23 02:00:00"}]}

    async def backup_task_run(self, ctx: Any, task_id: int) -> dict[str, Any]:
        return {"task_id": task_id, "started": True}

    async def snapshot_create(self, ctx: Any, share: str, desc: str) -> dict[str, Any]:
        return {"share": share, "snapshot": "GMT+00-2026.07.24-12.00.00", "desc": desc}

    async def container_logs(self, ctx: Any, container_id: str, lines: int) -> dict[str, Any]:
        return {"container_id": container_id,
                "lines": [f"log line {i}" for i in range(min(lines, 3))]}

    async def package_list(self, ctx: Any) -> dict[str, Any]:
        return {"packages": [{"id": "ContainerManager", "name": "Container Manager",
                             "status": "running", "version": "24.0.2"},
                            {"id": "HyperBackup", "name": "Hyper Backup",
                             "status": "running", "version": "4.0.0"}]}

    async def download_task_control(self, ctx: Any, task_id: str, action: str) -> dict[str, Any]:
        return {"task_id": task_id, "action": action, "ok": True}


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
# Live DSM backend (composes through chp.adapters.http)
# ---------------------------------------------------------------------------

class _DSMBackend:
    """Live Synology DSM backend via WebAPI, routed through chp.adapters.http."""

    def __init__(self, config: SynologyConfig) -> None:
        self._config = config
        self._sid: str | None = None
        self._versions: dict[str, tuple[int, int]] = {}  # api -> (minVersion, maxVersion)

    async def _req(self, ctx: Any, method: str, path: str,
                   params: dict[str, Any] | None = None,
                   form: dict[str, Any] | None = None) -> dict[str, Any]:
        """One DSM WebAPI call through the http adapter. Returns the http adapter's
        result data ({status_code, json, ...}); raises only if the transport itself
        is unavailable/denied — HTTP status codes are handled by callers."""
        base = self._config.resolved_url().rstrip("/")
        req: dict[str, Any] = {"method": method, "url": f"{base}{path}", "timeout": 30,
                               "verify": self._config.verify_ssl}  # DSM self-signed → verify off
        if params is not None:
            # Param VALUES (incl. passwd, _sid) are never evidenced — the http adapter
            # records only the bare url + sorted param KEYS.
            req["params"] = {k: str(v) for k, v in params.items()}
        if form is not None:
            req["body"] = urlencode(form)
            req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        result = await ctx.ainvoke(_HTTP_CAP, req)
        if not getattr(result, "success", False):
            raise RuntimeError(
                f"Synology {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        return result.data or {}

    async def _resolve_version(self, ctx: Any, api: str, preferred: int) -> int:
        """Clamp *preferred* to the version range the NAS actually exposes for *api*.

        DSM versions (esp. Container Manager vs. the old Docker package) advertise
        different API versions; requesting an unsupported one yields error code 104.
        SYNO.API.Info (public, no SID) reports the supported min/max so we negotiate
        instead of hardcoding. Result cached per api; falls back to *preferred*.
        """
        if api not in self._versions:
            lo, hi = 1, preferred
            try:
                data = await self._req(ctx, "GET", "/webapi/query.cgi", params={
                    "api": "SYNO.API.Info", "version": 1, "method": "query", "query": api})
                info = ((data.get("json") or {}).get("data") or {}).get(api) or {}
                lo = int(info.get("minVersion", 1))
                hi = int(info.get("maxVersion", preferred))
            except Exception:
                pass
            self._versions[api] = (lo, hi)
        lo, hi = self._versions[api]
        return max(lo, min(preferred, hi))

    async def _auth(self, ctx: Any) -> str:
        data = await self._req(ctx, "GET", "/webapi/auth.cgi", params={
            "api": "SYNO.API.Auth",
            "version": "3",
            "method": "login",
            "account": self._config.resolved_username(),
            "passwd": self._config.resolved_password(),  # value never evidenced
            "session": "FileStation",
            "format": "sid",
        })
        status = data.get("status_code")
        if status is not None and status >= 400:
            raise RuntimeError(f"DSM auth returned HTTP {status}")
        body = data.get("json") or {}
        if not body.get("success"):
            raise RuntimeError(f"DSM auth failed: {body.get('error', {}).get('code', 'unknown')}")
        return str(body["data"]["sid"])

    async def _sid_or_auth(self, ctx: Any) -> str:
        if not self._sid:
            self._sid = await self._auth(ctx)
        return self._sid

    async def _entry(self, ctx: Any, http_method: str, api: str, method: str,
                     version: int, **extra: Any) -> Any:
        """Call entry.cgi with SID + version negotiation, re-authing once on a stale SID — HTTP 403 OR
        a DSM body error code 119 ('SID not found') / 106 (session timeout), which arrive as HTTP 200
        + success:false and so wouldn't otherwise trigger a refresh."""
        sid = await self._sid_or_auth(ctx)
        version = await self._resolve_version(ctx, api, version)
        args = {"api": api, "version": version, "method": method, "_sid": sid, **extra}

        async def _call() -> dict[str, Any]:
            if http_method == "GET":
                return await self._req(ctx, "GET", "/webapi/entry.cgi", params=args)
            return await self._req(ctx, "POST", "/webapi/entry.cgi", form=args)

        def _stale(d: dict[str, Any]) -> bool:
            return d.get("status_code") == 403 or \
                (d.get("json") or {}).get("error", {}).get("code") in (119, 106)

        data = await _call()
        if _stale(data):
            self._sid = await self._auth(ctx)
            args["_sid"] = self._sid
            data = await _call()
        status = data.get("status_code")
        if status is not None and status >= 400:
            raise RuntimeError(f"DSM API {api}.{method} returned HTTP {status}")
        body = data.get("json") or {}
        if not body.get("success"):
            raise RuntimeError(f"DSM API {api}.{method} failed: {body.get('error', {})}")
        return body.get("data", {})

    async def file_list(self, ctx: Any, path: str, limit: int) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.FileStation.List", "list", version=2,
                                 folder_path=path, limit=limit, additional="size,time,owner")

    async def file_info(self, ctx: Any, path: str) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.FileStation.Info", "getinfo", version=2,
                                 path=path, additional="size,time,owner")

    async def task_list(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Core.TaskScheduler", "list", version=3)

    async def container_list(self, ctx: Any) -> dict[str, Any]:
        # SYNO.Docker.Container.list requires pagination params (else DSM code 114).
        return await self._entry(ctx, "GET", "SYNO.Docker.Container", "list", version=2,
                                 limit=-1, offset=0)

    async def container_start(self, ctx: Any, container_id: str) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.Docker.Container", "start", version=2,
                                 id=container_id)

    async def container_stop(self, ctx: Any, container_id: str) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.Docker.Container", "stop", version=2,
                                 id=container_id)

    async def download_create(self, ctx: Any, uri: str, dest_folder: str) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.DownloadStation.Task", "create", version=3,
                                 uri=uri, destination=dest_folder)

    # --- health / observability (read-only) ---
    # SYNO.Core.Storage.Volume/Disk .list return code 101 on DSM 7.3; the canonical combined
    # endpoint SYNO.Storage.CGI.Storage.load_info returns {volumes, disks, pools, ...} in one call.
    async def _storage_info(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Storage.CGI.Storage", "load_info", version=1)

    async def storage_volume_list(self, ctx: Any) -> dict[str, Any]:
        return {"volumes": (await self._storage_info(ctx)).get("volumes", [])}

    async def disk_smart_health(self, ctx: Any) -> dict[str, Any]:
        return {"disks": (await self._storage_info(ctx)).get("disks", [])}

    async def system_info(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Core.System", "info", version=1)

    async def system_utilization(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Core.System.Utilization", "get", version=1)

    async def backup_task_list(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Backup.Task", "list", version=1,
                                 additional="last_bkp_result,last_bkp_time")

    async def package_list(self, ctx: Any) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Core.Package.Server", "list", version=1)

    async def container_logs(self, ctx: Any, container_id: str, lines: int) -> dict[str, Any]:
        return await self._entry(ctx, "GET", "SYNO.Docker.Container.Log", "get", version=1,
                                 id=container_id, limit=lines)

    # --- governed writes (approval-gated at the cap layer) ---
    async def backup_task_run(self, ctx: Any, task_id: int) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.Backup.Task", "backup_start", version=1,
                                 task_id=task_id)

    async def snapshot_create(self, ctx: Any, share: str, desc: str) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.Core.Share.Snapshot", "create", version=1,
                                 name=share, desc=desc)

    async def download_task_control(self, ctx: Any, task_id: str, action: str) -> dict[str, Any]:
        return await self._entry(ctx, "POST", "SYNO.DownloadStation2.Task", action, version=2,
                                 id=task_id)


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
            result = await backend.file_list(ctx, path, limit)
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
            result = await backend.file_info(ctx, path)
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
            result = await backend.task_list(ctx)
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
            result = await backend.container_list(ctx)
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
            result = await backend.container_start(ctx, container_id)
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
            result = await backend.container_stop(ctx, container_id)
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
            result = await backend.download_create(ctx, uri, dest_folder)
        except Exception as exc:
            ctx.emit("synology_error", {"op": "download_create", "error": str(exc)[:_MAX_ERR]}, redacted=False)
            raise
        ctx.emit("synology_response", {"op": "download_create", "task_id": result.get("task_id")}, redacted=False)
        return result

    # ------------------------------------------------------------------
    # DSM health / observability + governed backup — added caps. `_op` DRYs the
    # request/response/error emit envelope the older caps inline.
    # ------------------------------------------------------------------
    async def _op(self, ctx: Any, op: str, backend_coro: Any, **meta: Any) -> Any:
        ctx.emit("synology_request", {"op": op, **meta}, redacted=False)
        try:
            result = await backend_coro
        except Exception as exc:
            ctx.emit("synology_error", {"op": op, "error": str(exc)[:_MAX_ERR], **meta},
                     redacted=False)
            raise
        ctx.emit("synology_response", {"op": op, **meta}, redacted=False)
        return result

    @capability(id="chp.adapters.synology.storage_volume_list", version="1.0.0",
                description="List DSM storage volumes: capacity, used, RAID/degraded state.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def storage_volume_list(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "storage_volume_list", self._backend().storage_volume_list(ctx))

    @capability(id="chp.adapters.synology.disk_smart_health", version="1.0.0",
                description="Per-disk status + SMART health + temperature.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def disk_smart_health(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "disk_smart_health", self._backend().disk_smart_health(ctx))

    @capability(id="chp.adapters.synology.system_info", version="1.0.0",
                description="DSM model, firmware version, serial, uptime.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def system_info(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "system_info", self._backend().system_info(ctx))

    @capability(id="chp.adapters.synology.system_utilization", version="1.0.0",
                description="Live CPU / memory / disk / network utilization.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def system_utilization(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "system_utilization", self._backend().system_utilization(ctx))

    @capability(id="chp.adapters.synology.backup_task_list", version="1.0.0",
                description="Hyper Backup tasks + last-run status.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def backup_task_list(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "backup_task_list", self._backend().backup_task_list(ctx))

    @capability(id="chp.adapters.synology.package_list", version="1.0.0",
                description="Installed DSM packages + running state.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False})
    async def package_list(self, ctx: Any, payload: Any) -> Any:
        return await self._op(ctx, "package_list", self._backend().package_list(ctx))

    @capability(id="chp.adapters.synology.container_logs", version="1.0.0",
                description="Tail a Container Manager container's logs.",
                category="edge", provider="synology", risk="low", emits=_EMITS,
                input_schema={"type": "object", "properties": {
                    "container_id": {"type": "string", "minLength": 1},
                    "lines": {"type": "integer", "minimum": 1, "maximum": 1000}},
                    "required": ["container_id"], "additionalProperties": False})
    async def container_logs(self, ctx: Any, payload: Any) -> Any:
        cid, lines = payload["container_id"], payload.get("lines", 100)
        return await self._op(ctx, "container_logs",
                              self._backend().container_logs(ctx, cid, lines), container_id=cid)

    @capability(id="chp.adapters.synology.backup_task_run", version="1.0.0",
                description="Trigger a Hyper Backup task by id (governed).",
                category="edge", provider="synology", risk="high",
                side_effects=["backup_start"], emits=_EMITS,
                input_schema={"type": "object", "properties": {
                    "task_id": {"type": "integer"}},
                    "required": ["task_id"], "additionalProperties": False})
    async def backup_task_run(self, ctx: Any, payload: Any) -> Any:
        tid = payload["task_id"]
        return await self._op(ctx, "backup_task_run",
                              self._backend().backup_task_run(ctx, tid), task_id=tid)

    @capability(id="chp.adapters.synology.snapshot_create", version="1.0.0",
                description="Create a btrfs snapshot of a shared folder (governed).",
                category="edge", provider="synology", risk="high",
                side_effects=["filesystem_snapshot"], emits=_EMITS,
                input_schema={"type": "object", "properties": {
                    "share": {"type": "string", "minLength": 1},
                    "desc": {"type": "string"}},
                    "required": ["share"], "additionalProperties": False})
    async def snapshot_create(self, ctx: Any, payload: Any) -> Any:
        share, desc = payload["share"], payload.get("desc", "chp")
        return await self._op(ctx, "snapshot_create",
                              self._backend().snapshot_create(ctx, share, desc), share=share)

    @capability(id="chp.adapters.synology.download_task_control", version="1.0.0",
                description="Pause / resume / delete a Download Station task.",
                category="edge", provider="synology", risk="medium",
                side_effects=["download_control"], emits=_EMITS,
                input_schema={"type": "object", "properties": {
                    "task_id": {"type": "string", "minLength": 1},
                    "action": {"type": "string", "enum": ["pause", "resume", "delete"]}},
                    "required": ["task_id", "action"], "additionalProperties": False})
    async def download_task_control(self, ctx: Any, payload: Any) -> Any:
        tid, action = payload["task_id"], payload["action"]
        return await self._op(ctx, "download_task_control",
                              self._backend().download_task_control(ctx, tid, action), action=action)
