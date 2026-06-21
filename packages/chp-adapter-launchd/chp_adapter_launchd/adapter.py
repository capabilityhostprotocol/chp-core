"""LaunchdAdapter — govern macOS launchd (LaunchAgent) services as CHP capabilities.

Manage long-running local services — start, stop, status, and install/uninstall
persistent LaunchAgents — with evidence. Built for CHP's own infrastructure
services (e.g. the TEI and vLLM Metal servers) so they survive reboot and can be
governed through the capability host.

All launchctl + plist I/O is isolated in _backends.py (the CLI-adapter convention
used by git/radicle/process); the adapter delegates and emits.

Evidence policy:
  Emitted: label, operation, pid, returncode, plist path, env *keys*, latency.
  NOT emitted: environment variable VALUES (may hold tokens), plist file contents.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from chp_core import BaseAdapter, capability

from ._backends import LaunchdBackend, make_backend

_EMITS = [
    "launchd_listed",
    "launchd_status_checked",
    "launchd_start_started",
    "launchd_start_completed",
    "launchd_start_failed",
    "launchd_stop_started",
    "launchd_stop_completed",
    "launchd_stop_failed",
    "launchd_install_started",
    "launchd_install_completed",
    "launchd_install_failed",
    "launchd_uninstall_completed",
    "service_health_checked",
]

_HTTP_CAP = "chp.adapters.http.request"

# Default model-server readiness probes; overridable in LaunchdConfig.
_DEFAULT_MODEL_PROBES = [
    {"name": "tei", "url": "http://localhost:8090/health", "expect_status": 200},
    {"name": "vllm", "url": "http://localhost:8092/v1/models", "expect_status": 200},
    {"name": "scout", "url": "http://localhost:8094/health", "expect_status": 200},
]

_DEFAULT_PREFIX = "com.chp."


@dataclass
class LaunchdConfig:
    """Config for LaunchdAdapter.

    ``managed_prefix`` — only labels with this prefix may be managed (safety: the
    adapter will not touch arbitrary system services). ``list`` is also scoped to it.
    ``model_probes`` — list of {name, url, expect_status} dicts for service_health
    readiness checks (defaults to TEI + vllm at their standard ports).
    """
    managed_prefix: str = _DEFAULT_PREFIX
    model_probes: list[dict] = field(default_factory=lambda: list(_DEFAULT_MODEL_PROBES))
    _backend: Any = field(default=None, repr=False)


class LaunchdAdapter(BaseAdapter):
    """Manage macOS LaunchAgent services as governed CHP capabilities."""

    adapter_id = "chp.adapters.launchd"
    adapter_name = "Launchd"
    adapter_description = (
        "Govern macOS launchd LaunchAgent services: list, status, start, stop, "
        "install (generate plist + bootstrap), uninstall."
    )
    adapter_category = "infrastructure"
    adapter_tags = ["launchd", "launchctl", "service", "macos", "daemon", "infrastructure"]

    def __init__(self, config: LaunchdConfig | None = None) -> None:
        self._config = config or LaunchdConfig()
        self.__backend: LaunchdBackend | None = None

    def _backend(self) -> LaunchdBackend:
        if self._config._backend is not None:
            return self._config._backend
        if self.__backend is None:
            self.__backend = make_backend()
        return self.__backend

    def _check_managed(self, label: str) -> None:
        if not label.startswith(self._config.managed_prefix):
            raise ValueError(
                f"Label {label!r} is not managed by this adapter "
                f"(must start with {self._config.managed_prefix!r})."
            )

    # ------------------------------------------------------------------
    # list
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.list",
        version="1.0.0",
        description="List CHP-managed launchd services (scoped to the managed label prefix).",
        category="infrastructure",
        provider="launchd",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def list(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        services = await asyncio.to_thread(self._backend().list_services, self._config.managed_prefix)
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_listed", {"service_count": len(services), "latency_ms": latency_ms}, redacted=False)
        return {"services": services, "service_count": len(services), "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.status",
        version="1.0.0",
        description="Report whether a launchd service is loaded/running, its pid, and last exit code.",
        category="infrastructure",
        provider="launchd",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"label": {"type": "string", "description": "Service label, e.g. com.chp.tei"}},
            "required": ["label"],
            "additionalProperties": False,
        },
    )
    async def status(self, ctx: Any, payload: dict) -> dict:
        label = payload["label"]
        self._check_managed(label)
        t0 = time.monotonic()
        result = await asyncio.to_thread(self._backend().status, label)
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_status_checked", {
            "label": label, "loaded": result.get("loaded"), "running": result.get("running"),
            "pid": result.get("pid"), "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # start
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.start",
        version="1.0.0",
        description="Start (bootstrap) a service if not loaded, or restart it (kickstart -k) if already loaded.",
        category="infrastructure",
        provider="launchd",
        risk="medium",
        side_effects=["process_start"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "plist_path": {"type": "string", "description": "Plist path (defaults to ~/Library/LaunchAgents/<label>.plist)"},
            },
            "required": ["label"],
            "additionalProperties": False,
        },
    )
    async def start(self, ctx: Any, payload: dict) -> dict:
        label = payload["label"]
        self._check_managed(label)
        plist_path = payload.get("plist_path")
        ctx.emit("launchd_start_started", {"label": label}, redacted=False)
        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(self._backend().start, label, plist_path)
        except Exception as exc:
            ctx.emit("launchd_start_failed", {"label": label, "error": str(exc)[:300]}, redacted=False)
            raise
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_start_completed", {
            "label": label, "action": result.get("action"), "ok": result.get("ok"),
            "returncode": result.get("returncode"), "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # stop
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.stop",
        version="1.0.0",
        description="Stop (bootout) a loaded launchd service.",
        category="infrastructure",
        provider="launchd",
        risk="medium",
        side_effects=["process_stop"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"label": {"type": "string"}},
            "required": ["label"],
            "additionalProperties": False,
        },
    )
    async def stop(self, ctx: Any, payload: dict) -> dict:
        label = payload["label"]
        self._check_managed(label)
        ctx.emit("launchd_stop_started", {"label": label}, redacted=False)
        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(self._backend().stop, label)
        except Exception as exc:
            ctx.emit("launchd_stop_failed", {"label": label, "error": str(exc)[:300]}, redacted=False)
            raise
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_stop_completed", {
            "label": label, "ok": result.get("ok"), "returncode": result.get("returncode"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # install
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.install",
        version="1.0.0",
        description=(
            "Generate a LaunchAgent plist from a service spec, write it to "
            "~/Library/LaunchAgents, and bootstrap it. Environment values are written "
            "to the plist but never recorded in evidence (only env keys)."
        ),
        category="infrastructure",
        provider="launchd",
        risk="high",
        side_effects=["file_write", "process_start"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "label": {"type": "string", "description": "Service label (must match the managed prefix)"},
                "program": {"type": "string", "description": "Absolute path to the executable"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Program arguments"},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Environment variables (values not evidenced)"},
                "working_dir": {"type": "string"},
                "stdout_path": {"type": "string"},
                "stderr_path": {"type": "string"},
                "run_at_load": {"type": "boolean", "default": True},
                "keep_alive": {"type": "boolean", "default": True},
            },
            "required": ["label", "program"],
            "additionalProperties": False,
        },
    )
    async def install(self, ctx: Any, payload: dict) -> dict:
        label = payload["label"]
        self._check_managed(label)
        spec = {k: payload[k] for k in payload if k != "label"}
        env_keys = sorted((payload.get("env") or {}).keys())
        ctx.emit("launchd_install_started", {
            "label": label, "program": payload["program"], "env_keys": env_keys,
        }, redacted=False)
        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(self._backend().install, label, spec)
        except Exception as exc:
            ctx.emit("launchd_install_failed", {"label": label, "error": str(exc)[:300]}, redacted=False)
            raise
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_install_completed", {
            "label": label, "plist_path": result.get("plist_path"), "ok": result.get("ok"),
            "env_keys": result.get("env_keys"), "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # uninstall
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.uninstall",
        version="1.0.0",
        description="Bootout a service and remove its LaunchAgent plist.",
        category="infrastructure",
        provider="launchd",
        risk="high",
        side_effects=["file_delete", "process_stop"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"label": {"type": "string"}},
            "required": ["label"],
            "additionalProperties": False,
        },
    )
    async def uninstall(self, ctx: Any, payload: dict) -> dict:
        label = payload["label"]
        self._check_managed(label)
        t0 = time.monotonic()
        result = await asyncio.to_thread(self._backend().uninstall, label)
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("launchd_uninstall_completed", {
            "label": label, "booted_out": result.get("booted_out"),
            "plist_removed": result.get("plist_removed"), "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # service_health
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.launchd.service_health",
        version="1.0.0",
        description=(
            "Report combined health: all com.chp.* launchd services (running/stopped) "
            "and model-server readiness probes (TEI, vllm) via the http transport."
        ),
        category="infrastructure",
        provider="launchd",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def service_health(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()

        # 1. Launchd service states
        services = await asyncio.to_thread(self._backend().list_services, self._config.managed_prefix)
        running_count = sum(1 for s in services if s.get("running"))

        # 2. Model-server readiness probes (fast, parallel, via http transport)
        model_results: list[dict] = []
        probe_tasks = [
            self._probe_model_server(ctx, p)
            for p in self._config.model_probes
        ]
        for coro in asyncio.as_completed(probe_tasks):
            model_results.append(await coro)

        overall_ok = (
            all(s.get("running") for s in services if s.get("label", "").endswith((".tei", ".vllm", ".mac")))
            and all(r["reachable"] for r in model_results)
        )

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("service_health_checked", {
            "service_count": len(services),
            "running_count": running_count,
            "model_probe_count": len(model_results),
            "ok": overall_ok,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "ok": overall_ok,
            "services": services,
            "model_servers": sorted(model_results, key=lambda r: r["name"]),
            "latency_ms": latency_ms,
        }

    async def _probe_model_server(self, ctx: Any, probe: dict) -> dict:
        """Probe one model server endpoint via the http transport (non-fatal on failure)."""
        name = probe["name"]
        url = probe["url"]
        expect = probe.get("expect_status", 200)
        t0 = time.monotonic()
        try:
            result = await ctx.ainvoke(_HTTP_CAP, {"method": "GET", "url": url, "timeout": 3.0})
            if getattr(result, "success", False):
                status = result.data.get("status_code")
                reachable = status == expect
            else:
                reachable = False
                status = None
        except Exception:
            reachable = False
            status = None
        return {
            "name": name,
            "url": url,
            "reachable": reachable,
            "status_code": status,
            "latency_ms": round((time.monotonic() - t0) * 1000),
        }
