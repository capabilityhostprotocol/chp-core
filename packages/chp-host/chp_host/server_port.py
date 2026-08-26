"""chp-server attachment: the governed adapter host as a port provider.

Registered under the ``chp_server.ports`` entry-point group as ``adapter_host``.
One attachment honestly fulfills four roles (DEC-SRV-004): a
``LocalCapabilityHost`` fuses Host identity, the 12-gate admission pipeline,
execution dispatch, and the evidence store behind one object — chp-server never
splits them.

chp-server discovers this lazily by entry point; importing chp_host is never
required for the base server (PKG-009).
"""

from __future__ import annotations

from pathlib import Path

from .profile import HostProfile
from .serve import build_adapter_host


class AdapterHostPort:
    roles = ("HostPort", "AdmissionPort", "ExecutionPort", "EvidencePort")
    source = "local"

    def __init__(self, adapters: list[str] | None = None, profile: str | None = None,
                 host_id: str | None = None, store: str | None = None,
                 adapter_configs: dict | None = None) -> None:
        self._profile_path = profile
        self._adapters = list(adapters or [])
        self._host_id = host_id
        self._store = store
        # Per-adapter provisioning config {name: {config_class, config}} so a
        # chp-server can serve CONFIGURED hardware/backend adapters (chp-home parity).
        self._adapter_configs = adapter_configs or {}
        self.host = None
        self.build_result = None

    def validate(self) -> None:
        if self._profile_path:
            p = HostProfile.load(Path(self._profile_path).expanduser())
            self._adapters = self._adapters or list(p.adapters)
            self._host_id = self._host_id or p.host_id
            self._store = self._store or str(p.store)
        if not self._adapters:
            raise ValueError(
                "adapter_host attachment needs 'adapters' or a 'profile' listing them")

    def start(self) -> None:
        self.host, self.build_result = build_adapter_host(
            self._adapters,
            host_id=self._host_id or "chp-host",
            store_path=self._store or ".chp/host.sqlite",
            configs=self._adapter_configs,
        )

    def health(self) -> str:
        if self.host is None:
            return "unavailable"
        # Degraded when some configured adapters could not register (fail-soft
        # build): the host serves, but not the full configured surface.
        if self.build_result and self.build_result.skipped:
            return "degraded"
        return "ready"

    def stop(self) -> None:
        self.host = None


class RouterPort:
    """Gateway attachment: MultiHostRouter as the served host (doc 12 §8).

    The router mediates remote fulfillment — it advertises the merged catalog
    and routes invocations, but local admission/execution stay truthfully
    absent: each remote Host admits its own work.
    """

    roles = ("HostPort", "FederationPort")
    source = "remote"

    def __init__(self, remotes: list[str] | None = None, selection: str = "first",
                 host_id: str = "chp-gateway", transports: list | None = None) -> None:
        self._remotes = list(remotes or [])
        self._selection = selection
        self._host_id = host_id
        self._transports = transports  # programmatic (tests / embedding)
        self.host = None  # the router; chp_core.http duck-types it

    def validate(self) -> None:
        if not self._remotes and not self._transports:
            raise ValueError("router_gateway attachment needs 'remotes' (base URLs)")

    def start(self) -> None:
        import asyncio
        from chp_core.transport import HttpTransport
        from .router import MultiHostRouter
        ts = self._transports or [HttpTransport(url) for url in self._remotes]
        self.host = MultiHostRouter(ts, selection=self._selection, host_id=self._host_id)
        asyncio.run(self.host.connect())
        self._health_cache = (0.0, "ready")

    def health(self) -> str:
        if self.host is None:
            return "unavailable"
        import asyncio
        import time
        # ponytail: 10s health cache — /ready must not probe the whole mesh per
        # request; drop the cache if per-call probing ever becomes required.
        ts, cached = getattr(self, "_health_cache", (0.0, "unavailable"))
        if time.monotonic() - ts < 10.0:
            return cached
        status = asyncio.run(self.host.health())["status"]
        state = {"ok": "ready", "degraded": "degraded"}.get(status, "unavailable")
        self._health_cache = (time.monotonic(), state)
        return state

    def stop(self) -> None:
        self.host = None


class McpImportSource:
    """MCP import source (INTRO-043): raw MCP tools become PROVENANCE-CARRYING
    semantic_mapping candidates — never CHP capabilities. Tool existence is not
    a capability: elevation to a governed capability requires an explicit,
    separately-approved mapping (which does not exist yet, on purpose).

    ``tools`` are pre-fetched MCP tool descriptors ({name, description,
    inputSchema}); live MCP-client fetching can wrap this without changing the
    introduction semantics.
    """

    def __init__(self, origin: str, tools: list[dict], *, source_id: str | None = None) -> None:
        if not origin:
            raise ValueError("McpImportSource needs the originating MCP server identity")
        self._origin = origin
        self._tools = list(tools)
        self.source_id = source_id or f"mcp:{origin}"

    def snapshot(self) -> dict:
        from chp_server.introduction import BATCH_SCHEMA_VERSION, canonical_digest
        candidates = []
        for tool in self._tools:
            payload = {"tool": tool["name"], "origin": self._origin, "raw": True,
                       "description": tool.get("description"),
                       "input_schema": tool.get("inputSchema")}
            candidates.append({"candidate_id": f"mcp-tool:{self._origin}:{tool['name']}",
                               "fact_class": "semantic_mapping", "payload": payload,
                               "canonical_digest": canonical_digest(payload)})
        return {"schema_version": BATCH_SCHEMA_VERSION, "source_id": self.source_id,
                "generation": canonical_digest({"tools": [c["canonical_digest"]
                                                           for c in candidates]})[:23],
                "complete_snapshot": True, "candidates": candidates}


class McpExportPort:
    """MCP export bridge: serve the governed host's capabilities as MCP tools
    over SSE (mcp.export). Requires the chp-host[mcp] extra; validate() fails
    with the install hint when it is absent — never a silent no-op feature.
    """

    roles = ("McpPort",)
    source = "adapter"
    requires = ("HostPort",)

    def __init__(self, bind: str = "127.0.0.1", port: int = 8810,
                 api_key: str | None = None, min_status: str = "draft") -> None:
        self._bind, self._port = bind, port
        self._api_key, self._min_status = api_key, min_status
        self._thread = None
        self._attachments = None

    def bind(self, attachments) -> None:
        self._attachments = attachments

    def validate(self) -> None:
        try:
            import mcp  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "mcp.export requires the MCP extra: pip install 'chp-host[mcp]'") from exc

    def start(self) -> None:
        import asyncio
        import threading
        from .mcp_server import run_mcp_server
        host_port = self._attachments.for_role("HostPort") if self._attachments else None
        host = getattr(host_port, "host", None)
        if host is None:
            raise RuntimeError("mcp.export requires a started HostPort attachment")

        def _serve() -> None:
            asyncio.run(run_mcp_server(
                host, transport="http", http_host=self._bind,
                http_port=self._port, api_key=self._api_key,
                min_status=self._min_status))

        self._thread = threading.Thread(target=_serve, daemon=True, name="chp-mcp-export")
        self._thread.start()

    def health(self) -> str:
        return "ready" if self._thread is not None and self._thread.is_alive() else "unavailable"

    def stop(self) -> None:
        # ponytail: daemon thread, no graceful uvicorn shutdown handle; add a
        # Server.should_exit latch if drain-clean MCP shutdown becomes required.
        self._thread = None
