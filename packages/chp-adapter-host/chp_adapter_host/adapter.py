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
        # upgrade it performs. Returns before the restart happens. The update CLI
        # writes its own ~/.chp/logs/host-update.log, so stdout can go to DEVNULL.
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        ctx.emit("host_update_scheduled", {"from_version": before, "pid": proc.pid})
        return {
            "from_version": before,
            "scheduled": True,
            "pid": proc.pid,
            "note": "Update runs detached; this host will restart shortly. "
                    "Re-check /health for the new host_version.",
        }
