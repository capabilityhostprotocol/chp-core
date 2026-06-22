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
        cmd = [sys.executable, "-m", "chp_host.cli", "update", "--restart"]
        if payload.get("version"):
            cmd += ["--version", str(payload["version"])]
        if payload.get("channel"):
            cmd += ["--channel", str(payload["channel"])]

        # Detached (new session) so it survives this host being restarted by the
        # upgrade it performs. Returns before the restart happens.
        #
        # Critical: a launchd/systemd service runs with a minimal environment
        # (often no HOME, truncated PATH). Without HOME, the child's pip cache and
        # ~/.chp log path break and the update silently no-ops. Inject a sane HOME
        # (from the passwd db) and a full PATH so the detached update behaves like
        # an interactive run.
        child_env = _service_safe_env()

        # Capture the detached child's stdout+stderr to a file so a failed remote
        # update is diagnosable (e.g. via filesystem.read_file over the mesh) —
        # not lost to DEVNULL. Use os.open (fd), so Popen can redirect to it.
        log_dir = os.path.join(child_env["HOME"], ".chp", "logs")
        os.makedirs(log_dir, exist_ok=True)
        fd = os.open(os.path.join(log_dir, "host-update-child.log"),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            proc = subprocess.Popen(
                cmd, stdout=fd, stderr=fd, start_new_session=True, env=child_env,
            )
        finally:
            os.close(fd)  # Popen duplicated the fd; close our copy

        ctx.emit("host_update_scheduled", {"from_version": before, "pid": proc.pid})
        return {
            "from_version": before,
            "scheduled": True,
            "pid": proc.pid,
            "note": "Update runs detached; this host will restart shortly. "
                    "Re-check /health for the new host_version.",
        }
