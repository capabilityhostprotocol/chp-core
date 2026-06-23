"""HostAdapter — report and update the CHP runtime on this node.

Two capabilities:

* ``version`` — report this node's chp-host version, platform, installed adapters.
* ``update``  — schedule a **detached** ``chp-host update --restart``. The host
  running this capability will be restarted by the upgrade, so the work must
  outlive it: we spawn the updater in a new session and return immediately
  (``scheduled: true``) *before* anything restarts. The caller re-checks
  ``/health`` to see the new version.

Depends only on chp-core. It does NOT import chp-host (it shells out to the
installed ``chp-host`` CLI) and discovers adapters via entry points, so there is
no dependency cycle.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Any

from chp_core import BaseAdapter, capability
from chp_core.stats import collect_host_stats


def _host_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("chp-host")
    except PackageNotFoundError:
        return "unknown"


def _installed_adapters() -> list[str]:
    from importlib.metadata import entry_points
    return sorted(ep.name for ep in entry_points(group="chp.adapters"))


def _service_safe_env() -> dict[str, str]:
    """A child environment safe for use under launchd/systemd (minimal env).

    Ensures HOME (the service env often lacks it, which breaks pip's cache and
    the ~/.chp log path) and a full PATH including /usr/sbin (where ioreg/sysctl
    and other tools live)."""
    import pwd
    env = dict(os.environ)
    home = env.get("HOME")
    if not home:
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except Exception:
            home = "/tmp"
        env["HOME"] = home
    extra = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/opt/homebrew/bin"
    env["PATH"] = (env.get("PATH", "") + ":" + extra).strip(":")
    return env


def _profile_path_from_argv() -> str | None:
    """The --profile path this host was started with (so install_adapter can add a
    new adapter to the very profile this serve process is running). The host adapter
    runs inside `chp-host serve --profile <path>`, so sys.argv carries it."""
    argv = sys.argv
    for i, a in enumerate(argv):
        if a == "--profile" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--profile="):
            return a.split("=", 1)[1]
    return None


def _spawn_detached_cli(args: list[str], log_name: str) -> int:
    """Spawn `python -m chp_host.cli <args>` detached, with a service-safe env,
    capturing the child's stdout+stderr to ~/.chp/logs/<log_name> (so a failed
    remote action is diagnosable, e.g. via filesystem.read_file over the mesh).
    Returns the child pid. Used by update + restart, which must outlive the
    service restart they trigger.
    """
    child_env = _service_safe_env()
    log_dir = os.path.join(child_env["HOME"], ".chp", "logs")
    os.makedirs(log_dir, exist_ok=True)
    fd = os.open(os.path.join(log_dir, log_name), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "chp_host.cli", *args],
            stdout=fd, stderr=fd, start_new_session=True, env=child_env,
        )
    finally:
        os.close(fd)  # Popen duplicated the fd; close our copy
    return proc.pid


class HostAdapter(BaseAdapter):
    adapter_id = "chp.adapters.host"
    adapter_name = "Host"
    adapter_description = "Report and update the CHP host runtime on this node."
    adapter_category = "infrastructure"
    adapter_tags = ["host", "update", "version", "infrastructure", "ops"]

    @capability(
        id="chp.adapters.host.version",
        version="1.0.0",
        description="Report this node's chp-host version, platform, and installed adapters.",
        category="infrastructure",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=["host_version_reported"],
        tags=["host", "version"],
    )
    async def version(self, ctx: Any, payload: dict) -> dict:
        info = {
            "host_version": _host_version(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "adapters": _installed_adapters(),
        }
        ctx.emit("host_version_reported", {"host_version": info["host_version"]})
        return info

    @capability(
        id="chp.adapters.host.stats",
        version="1.0.0",
        description="Report CPU load, memory, disk, GPU, and platform stats for this node.",
        category="infrastructure",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=["host_stats_reported"],
        tags=["host", "stats", "capacity"],
    )
    async def stats(self, ctx: Any, payload: dict) -> dict:
        result = collect_host_stats()
        ctx.emit("host_stats_reported", {
            "load_per_core": result.get("load_per_core"),
            "gpu": result.get("gpu"),
        })
        return result

    @capability(
        id="chp.adapters.host.update",
        version="1.0.0",
        description="Schedule a detached upgrade of this node's CHP packages, then restart its services.",
        category="infrastructure",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "version": {"type": "string", "description": "Pin chp-core/chp-host to this version."},
                "channel": {"type": "string", "enum": ["github", "pypi"]},
            },
            "additionalProperties": False,
        },
        emits=["host_update_scheduled"],
        tags=["host", "update", "ops"],
    )
    async def update(self, ctx: Any, payload: dict) -> dict:
        before = _host_version()
        # `chp-host update` restarts by default (the flag is --no-restart).
        args = ["update"]
        if payload.get("version"):
            args += ["--version", str(payload["version"])]
        if payload.get("channel"):
            args += ["--channel", str(payload["channel"])]
        pid = _spawn_detached_cli(args, "host-update-child.log")
        ctx.emit("host_update_scheduled", {"from_version": before, "pid": pid})
        return {
            "from_version": before,
            "scheduled": True,
            "pid": pid,
            "note": "Update runs detached; this host will restart shortly. "
                    "Re-check /health for the new host_version.",
        }

    @capability(
        id="chp.adapters.host.install_adapter",
        version="1.0.0",
        description=(
            "Install (or pull) a CHP adapter package onto this node, optionally add it "
            "to this host's profile, then restart so the new capabilities register. "
            "Detached — this host restarts shortly after scheduling."
        ),
        category="infrastructure",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "pip package name, e.g. 'chp-adapter-mlx'"},
                "version": {"type": "string", "description": "Pin to this version (ignored if url is set)."},
                "url": {"type": "string", "description": "Direct wheel/sdist URL (e.g. a GitHub release asset)."},
                "adapter_name": {"type": "string", "description": "Short entry-point name to add to this host's profile, e.g. 'mlx'."},
                "extras": {"type": "string", "description": "Optional-dependency extra to also install, e.g. 'serve' → chp-adapter-mlx[serve] (pulls the adapter's runtime tooling)."},
                "restart": {"type": "boolean", "default": True},
            },
            "required": ["package"],
            "additionalProperties": False,
        },
        emits=["host_adapter_install_scheduled"],
        tags=["host", "adapter", "install", "ops"],
    )
    async def install_adapter(self, ctx: Any, payload: dict) -> dict:
        package = str(payload.get("package") or "").strip()
        if not package:
            raise ValueError("package is required")
        args = ["install-adapter", package]
        if payload.get("url"):
            args += ["--url", str(payload["url"])]
        elif payload.get("version"):
            args += ["--version", str(payload["version"])]
        if payload.get("extras"):
            args += ["--extras", str(payload["extras"])]
        adapter_name = payload.get("adapter_name")
        profile = None
        if adapter_name:
            args += ["--adapter-name", str(adapter_name)]
            profile = _profile_path_from_argv()
            if profile:
                args += ["--profile", profile]
        if payload.get("restart") is False:
            args += ["--no-restart"]
        pid = _spawn_detached_cli(args, "host-install-adapter-child.log")
        ctx.emit("host_adapter_install_scheduled",
                 {"package": package, "adapter_name": adapter_name, "pid": pid})
        return {
            "scheduled": True,
            "pid": pid,
            "package": package,
            "adapter_name": adapter_name,
            "profile": profile,
            "note": "Install runs detached; this node restarts shortly. Re-check "
                    "/capabilities (or host.version adapters) for the new adapter.",
        }

    @capability(
        id="chp.adapters.host.restart",
        version="1.0.0",
        description="Restart this node's CHP services (detached, no upgrade).",
        category="infrastructure",
        risk="high",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=["host_restart_scheduled"],
        tags=["host", "restart", "ops"],
    )
    async def restart(self, ctx: Any, payload: dict) -> dict:
        # Detached so it survives the very services it restarts. Captures output
        # to ~/.chp/logs/host-restart-child.log for remote diagnosis.
        pid = _spawn_detached_cli(["restart"], "host-restart-child.log")
        ctx.emit("host_restart_scheduled", {"pid": pid})
        return {
            "scheduled": True,
            "pid": pid,
            "note": "Restart runs detached; this node's services bounce shortly.",
        }
