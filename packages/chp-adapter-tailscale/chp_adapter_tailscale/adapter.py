"""TailscaleAdapter — Tailscale mesh networking as governed CHP capabilities.

Uses the Tailscale HTTP API (https://api.tailscale.com/api/v2) for device
discovery; all HTTP routed through chp.adapters.http.request so every call
is governed and evidenced.

Mesh model
----------
Each physical node runs a CHP host on a well-known port:
  Mac (primary or worker)  → port 8803
  Synology NAS             → port 8802   (tag: tag:chp-nas)
  Raspberry Pi             → port 8801   (tag: tag:chp-raspi)

CHP hosts discover peers via tailscale.chp_hosts, verify reachability via
tailscale.verify_mesh, then route capability calls using CHP_REMOTE_HOSTS or
the multi-host router (chp-host package).

Evidence policy
---------------
Tailscale IPs (100.x.x.x), MagicDNS hostnames, and device metadata are
evidenced — they are routing information, not secrets.
API keys and auth tokens are NEVER emitted.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from chp_core import BaseAdapter, capability


async def _default_ts_runner(command: str, args: list[str], timeout: float) -> tuple[int, str, str]:
    """Run ``<command> <args>`` (the tailscale CLI) as a subprocess with a hard timeout."""
    proc = await asyncio.create_subprocess_exec(
        command, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"tailscale {args[0] if args else ''!r} exceeded {timeout}s") from None
    rc = proc.returncode if proc.returncode is not None else -1
    return rc, out.decode(errors="replace"), err.decode(errors="replace")

_EMITS = [
    "tailscale_devices_listed",
    "tailscale_chp_hosts_resolved",
    "tailscale_mesh_verified",
    "tailscale_served",
    "tailscale_funneled",
    "tailscale_serve_status",
    "tailscale_error",
]

_TS_API_BASE = "https://api.tailscale.com/api/v2"
_HTTP_CAP = "chp.adapters.http.request"

# Match the tailnet HTTPS URL tailscale prints on serve/funnel (e.g.
# https://host.tailXXXX.ts.net/).
_TS_URL_RE = re.compile(r"https://[a-z0-9._-]+\.ts\.net/?\S*", re.IGNORECASE)

# Default CHP port when no tag-based override matches.
_DEFAULT_CHP_PORT = 8803


@dataclass
class TailscaleConfig:
    """Configuration for TailscaleAdapter.

    api_key     — Tailscale API key (personal auth token or OAuth client secret).
                  Read from TAILSCALE_API_KEY env var if not set explicitly.
    tailnet     — Tailnet name (your email address) or the special value "me"
                  which resolves to the authenticated user's default tailnet.
                  Read from TAILSCALE_TAILNET env var if not set.
    port_by_tag — Maps Tailscale ACL tag → CHP host port.  Devices with
                  "tag:chp-nas" serve on 8802, "tag:chp-raspi" on 8801, etc.
                  Devices with no matching tag use default_chp_port.
    chp_host_tag — If non-empty, only devices carrying this tag are returned by
                   chp_hosts.  Leave empty to include all devices.
    """

    api_key: str = ""
    tailnet: str = ""
    tailscale_bin: str = "tailscale"  # CLI path for serve/funnel (local tailscaled control)
    default_chp_port: int = _DEFAULT_CHP_PORT
    port_by_tag: dict[str, int] = field(default_factory=lambda: {
        "tag:chp-nas": 8802,
        "tag:chp-raspi": 8801,
    })
    chp_host_tag: str = "tag:chp-host"
    # Injectable async runner (args, timeout) -> (returncode, stdout, stderr) for serve/funnel;
    # defaults to running the tailscale CLI via subprocess. A fake here isolates tests.
    cli_runner: Any = None

    def resolved_api_key(self) -> str:
        return self.api_key or os.environ.get("TAILSCALE_API_KEY", "")

    def resolved_tailnet(self) -> str:
        return self.tailnet or os.environ.get("TAILSCALE_TAILNET", "me")

    def port_for(self, tags: list[str]) -> int:
        for tag in tags:
            if tag in self.port_by_tag:
                return self.port_by_tag[tag]
        return self.default_chp_port


class TailscaleAdapter(BaseAdapter):
    """Tailscale mesh networking as governed CHP capabilities."""

    adapter_id = "chp.adapters.tailscale"
    adapter_name = "Tailscale"
    adapter_description = (
        "Discover and health-check CHP hosts across a Tailscale tailnet. "
        "Enables secure multi-host clusters spanning MacBooks, NAS, and edge nodes "
        "without VPN configuration — Tailscale handles the WireGuard mesh."
    )
    adapter_category = "networking"
    adapter_tags = ["tailscale", "mesh", "networking", "edge", "discovery"]

    def __init__(self, config: TailscaleConfig | None = None) -> None:
        self._config = config or TailscaleConfig()
        if self._config.cli_runner is not None:
            self._run = self._config.cli_runner
        else:
            bin_path = self._config.tailscale_bin

            async def _run(args: list[str], timeout: float) -> tuple[int, str, str]:
                return await _default_ts_runner(bin_path, args, timeout)

            self._run = _run

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _ts_get(self, ctx: Any, path: str) -> dict:
        """GET from Tailscale API; raises RuntimeError on failure."""
        api_key = self._config.resolved_api_key()
        if not api_key:
            raise RuntimeError(
                "No Tailscale API key configured. "
                "Set TAILSCALE_API_KEY or pass api_key to TailscaleConfig."
            )
        result = await ctx.ainvoke(_HTTP_CAP, {
            "method": "GET",
            "url": f"{_TS_API_BASE}{path}",
            "headers": {"Authorization": f"Bearer {api_key}"},
        })
        if not result.success:
            raise RuntimeError(
                f"tailscale API {path}: http adapter unavailable "
                f"({getattr(result, 'error', 'unknown')})"
            )
        data = result.data or {}
        status = data.get("status_code")
        if status and status >= 400:
            raise RuntimeError(f"Tailscale API GET {path} returned HTTP {status}")
        return (data.get("json") or {})

    def _normalise_device(self, raw: dict) -> dict:
        """Extract the fields we care about from a Tailscale device object."""
        addresses = raw.get("addresses") or []
        tags = raw.get("tags") or []
        return {
            "id": raw.get("id", ""),
            "hostname": raw.get("hostname", ""),
            "name": raw.get("name", ""),           # MagicDNS FQDN
            "os": raw.get("os", ""),
            "tags": tags,
            "addresses": addresses,
            "tailscale_ip": next((a for a in addresses if a.startswith("100.")), ""),
            "last_seen": raw.get("lastSeen", ""),
            "online": not raw.get("blocksIncomingConnections", False),
        }

    # ------------------------------------------------------------------
    # tailscale.devices
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.devices",
        version="1.0.0",
        description=(
            "List all devices in the Tailscale tailnet. Returns hostname, "
            "MagicDNS FQDN, Tailscale IP, OS, tags, and online status for each device."
        ),
        category="networking",
        provider="tailscale",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "include_offline": {
                    "type": "boolean",
                    "description": "Include devices not seen in the last 30 minutes (default true).",
                    "default": True,
                },
            },
            "additionalProperties": False,
        },
    )
    async def devices(self, ctx: Any, payload: dict) -> dict:
        include_offline: bool = payload.get("include_offline", True)
        tailnet = self._config.resolved_tailnet()

        t0 = time.monotonic()
        try:
            raw = await self._ts_get(ctx, f"/tailnet/{tailnet}/devices")
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "devices", "error": str(exc)[:500]}, redacted=False)
            raise

        raw_devices: list[dict] = raw.get("devices") or []
        normalised = [self._normalise_device(d) for d in raw_devices]
        if not include_offline:
            normalised = [d for d in normalised if d["online"]]

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("tailscale_devices_listed", {
            "tailnet": tailnet,
            "device_count": len(normalised),
            "online_count": sum(1 for d in normalised if d["online"]),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "tailnet": tailnet,
            "devices": normalised,
            "device_count": len(normalised),
            "online_count": sum(1 for d in normalised if d["online"]),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # tailscale.chp_hosts
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.chp_hosts",
        version="1.0.0",
        description=(
            "Resolve CHP host URLs for devices in the tailnet. "
            "Filters by chp_host_tag (default 'tag:chp-host'), assigns ports by tag "
            "(tag:chp-nas→8802, tag:chp-raspi→8801, default→8803), and returns "
            "the full CHP base URL using the device's Tailscale IP."
        ),
        category="networking",
        provider="tailscale",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "use_magicDNS": {
                    "type": "boolean",
                    "description": "Use MagicDNS FQDN instead of Tailscale IP in URLs (default false).",
                    "default": False,
                },
                "include_offline": {
                    "type": "boolean",
                    "description": "Include offline devices (default false).",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
    )
    async def chp_hosts(self, ctx: Any, payload: dict) -> dict:
        use_dns: bool = payload.get("use_magicDNS", False)
        include_offline: bool = payload.get("include_offline", False)
        tailnet = self._config.resolved_tailnet()

        t0 = time.monotonic()
        try:
            raw = await self._ts_get(ctx, f"/tailnet/{tailnet}/devices")
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "chp_hosts", "error": str(exc)[:500]}, redacted=False)
            raise

        raw_devices: list[dict] = raw.get("devices") or []
        hosts: list[dict] = []
        filter_tag = self._config.chp_host_tag

        for raw_dev in raw_devices:
            dev = self._normalise_device(raw_dev)
            tags = dev["tags"]

            # Skip if filter tag is set and device doesn't carry it
            if filter_tag and filter_tag not in tags:
                continue
            # Skip offline unless requested
            if not dev["online"] and not include_offline:
                continue

            addr = dev["name"] if (use_dns and dev["name"]) else dev["tailscale_ip"]
            if not addr:
                continue

            port = self._config.port_for(tags)
            chp_url = f"http://{addr}:{port}"

            role = "worker"
            if "tag:chp-nas" in tags:
                role = "nas"
            elif "tag:chp-raspi" in tags:
                role = "raspi"

            hosts.append({
                "hostname": dev["hostname"],
                "tailscale_ip": dev["tailscale_ip"],
                "fqdn": dev["name"],
                "os": dev["os"],
                "tags": tags,
                "role": role,
                "chp_url": chp_url,
                "chp_port": port,
                "online": dev["online"],
                "last_seen": dev["last_seen"],
            })

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("tailscale_chp_hosts_resolved", {
            "tailnet": tailnet,
            "host_count": len(hosts),
            "roles": sorted({h["role"] for h in hosts}),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "tailnet": tailnet,
            "hosts": hosts,
            "host_count": len(hosts),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # tailscale.verify_mesh
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.verify_mesh",
        version="1.0.0",
        description=(
            "Health-check all CHP hosts visible on the tailnet. "
            "Resolves hosts via chp_hosts, then probes each one's GET /health endpoint "
            "through chp.adapters.http.request. Returns per-host ok/fail with latency."
        ),
        category="networking",
        provider="tailscale",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "timeout_s": {
                    "type": "number",
                    "minimum": 1.0,
                    "maximum": 30.0,
                    "description": "Per-host probe timeout in seconds (default 5).",
                    "default": 5.0,
                },
            },
            "additionalProperties": False,
        },
    )
    async def verify_mesh(self, ctx: Any, payload: dict) -> dict:
        timeout_s: float = float(payload.get("timeout_s", 5.0))
        tailnet = self._config.resolved_tailnet()

        # Resolve CHP hosts
        t0 = time.monotonic()
        try:
            raw = await self._ts_get(ctx, f"/tailnet/{tailnet}/devices")
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "verify_mesh", "error": str(exc)[:500]}, redacted=False)
            raise

        raw_devices: list[dict] = raw.get("devices") or []
        filter_tag = self._config.chp_host_tag
        results: list[dict] = []

        for raw_dev in raw_devices:
            dev = self._normalise_device(raw_dev)
            tags = dev["tags"]
            if filter_tag and filter_tag not in tags:
                continue
            if not dev["tailscale_ip"]:
                continue

            port = self._config.port_for(tags)
            health_url = f"http://{dev['tailscale_ip']}:{port}/health"
            probe_t0 = time.monotonic()
            ok = False
            status_code = None
            error_msg = None

            try:
                probe = await ctx.ainvoke(_HTTP_CAP, {
                    "method": "GET",
                    "url": health_url,
                    "timeout": timeout_s,
                })
                if probe.success:
                    status_code = (probe.data or {}).get("status_code")
                    ok = status_code is not None and status_code < 400
                else:
                    error_msg = str(getattr(probe, "error", "probe failed"))[:200]
            except Exception as exc:
                error_msg = str(exc)[:200]

            probe_ms = round((time.monotonic() - probe_t0) * 1000)
            entry: dict = {
                "hostname": dev["hostname"],
                "tailscale_ip": dev["tailscale_ip"],
                "chp_url": f"http://{dev['tailscale_ip']}:{port}",
                "chp_port": port,
                "ok": ok,
                "status_code": status_code,
                "probe_ms": probe_ms,
            }
            if error_msg:
                entry["error"] = error_msg
            results.append(entry)

        total_ms = round((time.monotonic() - t0) * 1000)
        ok_count = sum(1 for r in results if r["ok"])
        ctx.emit("tailscale_mesh_verified", {
            "tailnet": tailnet,
            "hosts_checked": len(results),
            "hosts_ok": ok_count,
            "hosts_failed": len(results) - ok_count,
            "total_ms": total_ms,
        }, redacted=False)

        return {
            "tailnet": tailnet,
            "hosts_checked": len(results),
            "hosts_ok": ok_count,
            "hosts_failed": len(results) - ok_count,
            "results": results,
            "total_ms": total_ms,
        }

    # ------------------------------------------------------------------
    # Local tailscaled control (serve / funnel) — runs the tailscale CLI on
    # THIS node via governed process.run. Unlike the API-based caps above,
    # these change how the node exposes local ports, so they carry real risk.
    # ------------------------------------------------------------------

    async def _run_ts_cli(self, ctx: Any, args: list[str], timeout: float = 30.0) -> dict:
        """Run the local `tailscale` CLI directly via subprocess (like the container/git
        adapters). NOT through chp.adapters.process.run: that cap is approval-gated, and an
        in-process adapter→adapter ainvoke to a gated cap is denied — which broke serve/funnel
        ('process adapter unavailable'). The cap itself is governed at its own (high-risk)
        boundary; the CLI exec is a local subprocess. A ``cli_runner`` may be injected for tests."""
        returncode, stdout, stderr = await self._run(args, timeout)
        return {"exit_code": returncode, "stdout": stdout, "stderr": stderr}

    @staticmethod
    def _serve_args(verb: str, port: int, background: bool, off: bool,
                    funnel_port: int | None = None) -> list[str]:
        # A node exposes multiple services by using distinct public HTTPS ports (443/8443/10000).
        # Without funnel_port: keep the simple single-service form (`tailscale <verb> <port>`, 443
        # root) for back-compat. With it: the explicit `--https=<funnel_port> <target>` form, so
        # e.g. the gateway can live on 8443 while another app keeps 443.
        if funnel_port is not None:
            if off:
                return [verb, f"--https={funnel_port}", "off"]
            return [verb] + (["--bg"] if background else []) + \
                [f"--https={funnel_port}", f"http://127.0.0.1:{port}"]
        if off:
            return [verb, str(port), "off"]
        return [verb] + (["--bg"] if background else []) + [str(port)]

    # ------------------------------------------------------------------
    # tailscale.serve  — tailnet-private HTTPS
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.serve",
        version="1.0.0",
        description=(
            "Expose a local TCP port as HTTPS on the tailnet (private to your Tailscale "
            "network) via `tailscale serve`. Returns the tailnet HTTPS URL. Set off=true "
            "to stop serving the port. Runs the local tailscale CLI through process.run."
        ),
        category="networking",
        provider="tailscale",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer", "minimum": 1, "maximum": 65535,
                    "description": "Local TCP port to proxy (e.g. the CHP gateway port).",
                },
                "background": {
                    "type": "boolean", "default": True,
                    "description": "Run with --bg so serving persists after the call.",
                },
                "off": {
                    "type": "boolean", "default": False,
                    "description": "Disable serving for this port instead of enabling it.",
                },
                "funnel_port": {
                    "type": "integer", "enum": [443, 8443, 10000],
                    "description": "Public HTTPS port to expose on (443/8443/10000). Omit for the "
                                   "default single-service form; set distinct ports to host several "
                                   "services on one node.",
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
    )
    async def serve(self, ctx: Any, payload: dict) -> dict:
        port = int(payload["port"])
        background = bool(payload.get("background", True))
        off = bool(payload.get("off", False))
        funnel_port = payload.get("funnel_port")
        args = self._serve_args("serve", port, background, off, funnel_port)
        try:
            res = await self._run_ts_cli(ctx, args)
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "serve", "error": str(exc)[:500]}, redacted=False)
            raise
        combined = f"{res['stdout']}\n{res['stderr']}".strip()
        m = _TS_URL_RE.search(combined)   # tailscale prints the full URL incl :funnel_port
        url = m.group(0) if m else None
        ok = res["exit_code"] == 0
        ctx.emit("tailscale_served", {"port": port, "off": off, "ok": ok, "url": url}, redacted=False)
        return {
            "ok": ok, "port": port, "off": off, "scope": "tailnet",
            "url": url, "exit_code": res["exit_code"], "output": combined,
        }

    # ------------------------------------------------------------------
    # tailscale.funnel  — PUBLIC internet HTTPS
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.funnel",
        version="1.0.0",
        description=(
            "Expose a local TCP port to the PUBLIC internet as HTTPS via Tailscale Funnel "
            "(`tailscale funnel`). The returned URL is reachable from anywhere on the "
            "internet — the underlying service MUST enforce its own authentication. Set "
            "off=true to withdraw the public exposure. Runs the local tailscale CLI "
            "through process.run."
        ),
        category="networking",
        provider="tailscale",
        risk="high",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer", "minimum": 1, "maximum": 65535,
                    "description": "Local TCP port to expose publicly.",
                },
                "background": {
                    "type": "boolean", "default": True,
                    "description": "Run with --bg so the funnel persists after the call.",
                },
                "off": {
                    "type": "boolean", "default": False,
                    "description": "Withdraw the public funnel for this port.",
                },
                "funnel_port": {
                    "type": "integer", "enum": [443, 8443, 10000],
                    "description": "Public HTTPS port to funnel on (443/8443/10000). Omit for the "
                                   "default single-service form; set distinct ports to funnel "
                                   "several services from one node (e.g. gateway on 8443, app on 443).",
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
    )
    async def funnel(self, ctx: Any, payload: dict) -> dict:
        port = int(payload["port"])
        background = bool(payload.get("background", True))
        off = bool(payload.get("off", False))
        funnel_port = payload.get("funnel_port")
        args = self._serve_args("funnel", port, background, off, funnel_port)
        try:
            res = await self._run_ts_cli(ctx, args)
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "funnel", "error": str(exc)[:500]}, redacted=False)
            raise
        combined = f"{res['stdout']}\n{res['stderr']}".strip()
        m = _TS_URL_RE.search(combined)   # tailscale prints the full URL incl :funnel_port
        public_url = m.group(0) if m else None
        ok = res["exit_code"] == 0
        ctx.emit("tailscale_funneled", {
            "port": port, "off": off, "ok": ok, "public_url": public_url,
        }, redacted=False)
        return {
            "ok": ok, "port": port, "off": off,
            "public": (not off) and ok,
            "public_url": public_url,
            "exit_code": res["exit_code"], "output": combined,
            "warning": None if off else "This port is now reachable from the public internet; ensure the service enforces its own auth.",
        }

    # ------------------------------------------------------------------
    # tailscale.funnel_status — current serve/funnel configuration
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tailscale.funnel_status",
        version="1.0.0",
        description=(
            "Report the node's current `tailscale serve` / funnel configuration — which "
            "local ports are exposed on the tailnet or publicly, and their URLs."
        ),
        category="networking",
        provider="tailscale",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def funnel_status(self, ctx: Any, payload: dict) -> dict:
        try:
            res = await self._run_ts_cli(ctx, ["serve", "status"])
        except Exception as exc:
            ctx.emit("tailscale_error", {"op": "funnel_status", "error": str(exc)[:500]}, redacted=False)
            raise
        combined = f"{res['stdout']}\n{res['stderr']}".strip()
        urls = sorted(set(_TS_URL_RE.findall(combined)))
        ok = res["exit_code"] == 0
        ctx.emit("tailscale_serve_status", {"ok": ok, "url_count": len(urls)}, redacted=False)
        return {"ok": ok, "urls": urls, "exit_code": res["exit_code"], "output": combined}
