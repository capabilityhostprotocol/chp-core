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

import getpass
import glob
import os
import platform
import re
import shutil
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


# ---------------------------------------------------------------------------
# Node setup introspection (host.facts) — turns ad-hoc spelunking into one call.
# ---------------------------------------------------------------------------

def _facts_env() -> dict:
    """Env with common tool dirs prepended to PATH (rad/claude/homebrew live off the bare PATH)."""
    env = dict(os.environ)
    extra = [os.path.expanduser(p) for p in
             ("~/.radicle/bin", "~/.local/bin", "~/.npm-global/bin", "~/.cargo/bin")] + ["/opt/homebrew/bin"]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


def _facts_sh(args: list[str], timeout: int = 10) -> str:
    """Run a command on the augmented PATH; return stripped stdout ('' on any failure)."""
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=_facts_env())
        return (out.stdout or "").strip()
    except Exception:
        return ""


def _facts_tool(name: str) -> dict:
    """Locate a binary on the augmented PATH + its version (best-effort)."""
    path = shutil.which(name, path=_facts_env()["PATH"])
    if not path:
        return {"present": False}
    info = {"present": True, "path": path}
    ver = _facts_sh([path, "--version"], timeout=8)
    if ver:
        info["version"] = ver.splitlines()[0][:60]
    return info


class HostAdapter(BaseAdapter):
    adapter_id = "chp.adapters.host"
    adapter_name = "Host"
    adapter_description = "Report and update the CHP host runtime on this node."
    adapter_category = "infrastructure"
    adapter_tags = ["host", "update", "version", "infrastructure", "ops"]

    def on_register(self, host: Any) -> None:
        self._host = host  # for the capability catalog (host.discover)

    @capability(
        id="chp.adapters.host.discover",
        version="1.0.0",
        description="List this node's capability catalog (id, risk, category, adapter), with optional "
                    "namespace/category/risk filters. Read-only — the mesh-invokable view of GET /capabilities.",
        category="infrastructure",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "namespace": {"type": "string",
                              "description": "Prefix filter on capability id, e.g. 'chp.adapters.git.'"},
                "category": {"type": "string", "description": "Exact category filter."},
                "risk": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "ids_only": {"type": "boolean", "description": "Return just the sorted capability id list."},
            },
            "additionalProperties": False,
        },
        emits=["host_catalog_reported"],
        tags=["host", "discover", "catalog"],
    )
    async def discover(self, ctx: Any, payload: dict) -> dict:
        host = getattr(self, "_host", None)
        if host is None:
            return {"error": "host catalog unavailable (adapter not registered to a host)"}
        kwargs = {k: payload[k] for k in ("namespace", "category", "risk") if payload.get(k)}
        desc = host.discover(**kwargs) or {}
        caps = desc.get("capabilities", [])
        adapters = sorted({c["id"].split(".")[2] for c in caps
                           if c.get("id") and c["id"].count(".") >= 2})
        ctx.emit("host_catalog_reported", {"count": len(caps), "adapters": len(adapters)})
        if payload.get("ids_only"):
            return {"count": len(caps), "adapters": adapters,
                    "capability_ids": sorted(c.get("id") for c in caps if c.get("id"))}
        slim = [{"id": c.get("id"), "risk": c.get("risk"), "category": c.get("category"),
                 "description": (c.get("description") or "")[:120]} for c in caps]
        return {"count": len(caps), "adapters": adapters, "capabilities": slim}

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
        id="chp.adapters.host.facts",
        version="1.0.0",
        description="Introspect THIS node's setup in one call: host/arch/python, toolchain (claude/codex/rad/"
                    "git paths+versions), launchd services, radicle identity/homes/node/seed-policies, and rad "
                    "repo checkouts. The 'how is this node configured' view (Ansible-facts-shaped). Runs locally "
                    "on whichever node it is routed to.",
        category="infrastructure",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "sections": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["host", "tools", "services", "radicle", "repos"]},
                    "description": "Subset of fact sections to gather (default: all).",
                },
            },
            "additionalProperties": False,
        },
        emits=["host_facts_reported"],
        tags=["host", "facts", "introspection", "setup", "ops"],
    )
    async def facts(self, ctx: Any, payload: dict) -> dict:
        sections = set(payload.get("sections") or ["host", "tools", "services", "radicle", "repos"])
        out: dict[str, Any] = {}

        if "host" in sections:
            try:
                user = getpass.getuser()
            except Exception:
                user = os.environ.get("USER", "")
            out["host"] = {
                "hostname": platform.node(), "platform": platform.platform(),
                "arch": platform.machine(), "user": user,
                "python": sys.executable, "home": os.path.expanduser("~"),
            }

        if "tools" in sections:
            out["tools"] = {n: _facts_tool(n) for n in ("claude", "codex", "gemini", "rad", "git", "node")}

        if "services" in sections:
            ll = _facts_sh(["launchctl", "list"])
            out["services"] = sorted({
                line.split()[-1] for line in ll.splitlines()
                if line.split() and ("chp" in line.lower() or "rad" in line.lower())
            })[:25]

        if "radicle" in sections:
            rad: dict[str, Any] = {}
            for line in _facts_sh(["rad", "self"]).splitlines():
                low = line.strip().lower()
                if low.startswith("alias"):
                    rad["alias"] = line.split(None, 1)[-1].strip()
                elif low.startswith("did"):
                    rad["did"] = line.split(None, 1)[-1].strip()  # did:key is a public id (NID not surfaced)
            rad["homes"] = sorted(os.path.basename(p) for p in glob.glob(os.path.expanduser("~/.radicle*")))
            node = _facts_sh(["rad", "node", "status"])
            rad["node_running"] = "running" in node.lower() and "not running" not in node.lower()
            seed = _facts_sh(["rad", "seed"])
            rad["seeded_repos"] = sum(1 for line in seed.splitlines()
                                      if line.strip().startswith("│") and "rad:" in line)
            out["radicle"] = rad

        if "repos" in sections:
            repos = []
            for line in _facts_sh(["rad", "ls"]).splitlines():
                m = re.search(r"rad:[0-9a-zA-Z]+", line)
                if m and line.strip().startswith("│"):
                    name = line.strip("│").split()[0] if line.strip("│").split() else ""
                    repos.append({"name": name, "rid": m.group(0)})
            out["repos"] = repos[:40]

        tools_present = sum(1 for t in out.get("tools", {}).values() if t.get("present"))
        ctx.emit("host_facts_reported",
                 {"sections": sorted(out.keys()), "tools_present": tools_present})
        return out

    @capability(
        id="chp.adapters.host.topology",
        version="1.0.0",
        description="Mesh connectivity view from this node: the radicle peer graph (who it's connected to) "
                    "+ Tailscale device status (which mesh nodes are online). 'Where the nodes are connected'.",
        category="infrastructure",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=["host_topology_reported"],
        tags=["host", "topology", "mesh", "connectivity", "ops"],
    )
    async def topology(self, ctx: Any, payload: dict) -> dict:
        # Radicle peer graph (connected = "✓" marker; address shown for reachable peers).
        peers = []
        for line in _facts_sh(["rad", "node", "status"]).splitlines():
            if "│" not in line:
                continue
            nid = re.search(r"z6Mk[0-9A-Za-z]{20,}", line)
            addr = re.search(r"\b(100\.\d+\.\d+\.\d+:\d+|[\w.-]+:\d{2,5})\b", line)
            if nid:
                peers.append({"nid": nid.group(0)[:14] + "…", "address": addr.group(0) if addr else "",
                              "connected": "✓" in line})

        # Tailscale device status (mesh-node reachability).
        ts = _facts_sh(["tailscale", "status"]) or \
            _facts_sh(["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "status"])
        devices = []
        for line in ts.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("100."):
                devices.append({"ip": parts[0], "name": parts[1],
                                "os": parts[3] if len(parts) >= 4 else "",
                                "online": "offline" not in line.lower()})

        result = {"radicle_peers": peers,
                  "radicle_connected": sum(1 for p in peers if p["connected"]),
                  "tailscale_devices": devices[:50],
                  "tailscale_online": sum(1 for d in devices if d["online"])}
        ctx.emit("host_topology_reported",
                 {"peers": len(peers), "devices": len(devices), "online": result["tailscale_online"]})
        return result

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
        emits=["host_adapter_install_scheduled", "host_adapter_installed"],
        tags=["host", "adapter", "install", "ops"],
    )
    async def install_adapter(self, ctx: Any, payload: dict) -> dict:
        package = str(payload.get("package") or "").strip()
        if not package:
            raise ValueError("package is required")
        args = ["install-adapter", package]
        # Deferred-evidence coordinates (chp-v0.2.md §7): the detached install
        # appends `host_adapter_installed` (version + record_sha256 provenance)
        # under THIS correlation with a causal edge to this invocation.
        store_path = getattr(getattr(getattr(ctx, "host", None), "store", None), "path", None)
        if store_path and store_path != ":memory:":
            child = ctx.child_correlation()
            args += ["--evidence-store", str(store_path),
                     "--correlation-id", str(child.correlation_id),
                     "--host-id", str(getattr(ctx.host, "host_id", "") or "unknown")]
            if child.causation_id:
                args += ["--causation-id", str(child.causation_id)]
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
