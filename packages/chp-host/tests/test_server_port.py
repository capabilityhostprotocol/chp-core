"""AdapterHostPort — the chp_server.ports attachment (Phase 2 integration).

Needs chp-server installed (it is, editable, in chp-dev); skipped elsewhere so
chp-host keeps no test-time dependency on it.
"""

from __future__ import annotations

import json

import pytest

chp_server = pytest.importorskip("chp_server")

from chp_host.server_port import AdapterHostPort  # noqa: E402


def test_validate_requires_adapters():
    with pytest.raises(ValueError, match="adapters"):
        AdapterHostPort().validate()


def test_profile_file_supplies_adapters(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text(json.dumps({
        "host_id": "profile-host", "adapters": ["memory"],
        "store": str(tmp_path / "p.sqlite")}))
    port = AdapterHostPort(profile=str(profile))
    port.validate()
    port.start()
    assert port.host is not None and port.host.host_id == "profile-host"
    assert port.health() in ("ready", "degraded")
    port.stop()
    assert port.health() == "unavailable"


def test_entry_point_discovery_and_host_profile(tmp_path):
    """chp-server loads the attachment by entry point name and serves its host."""
    from chp_server import Server, ServerConfig

    config = ServerConfig(
        port=0, profile="host", store=str(tmp_path / "srv.sqlite"),
        attachments={"adapter_host": {
            "adapters": ["memory"], "host_id": "attached-adapter-host",
            "store": str(tmp_path / "host.sqlite")}})
    s = Server(config)
    s.start()
    try:
        assert s.ready()["ready"] is True
        by_name = {f.feature: f.state for f in s.features.snapshot(lifecycle=s.state)}
        # LocalCapabilityHost fulfills all four roles (DEC-SRV-004) — the
        # invocation features light up too; resolve/mcp/federation stay unsupported.
        assert by_name["capability.discovery"] in ("ready", "degraded")
        assert by_name["invocation.local"] in ("ready", "degraded")
        assert by_name["capability.resolve"] == "unsupported"
        assert by_name["mcp.import"] == "unsupported"
    finally:
        s.stop()


def test_adapter_host_provisions_configured_adapter(tmp_path):
    """chp-server provisions a CONFIGURED hardware/backend adapter (chp-home
    parity): filesystem with allowed_roots, enforced through the served host."""
    import json
    import urllib.error
    import urllib.request

    pytest.importorskip("chp_adapter_filesystem")
    from chp_server import Server, ServerConfig

    allowed = tmp_path / "sandbox"; allowed.mkdir()
    s = Server(ServerConfig(port=0, profile="local", store=str(tmp_path / "s.sqlite"),
                            attachments={"adapter_host": {
                                "adapters": ["filesystem"], "host_id": "hw-node",
                                "store": str(tmp_path / "h.sqlite"),
                                "adapter_configs": {"filesystem": {
                                    "config_class": "chp_adapter_filesystem:FilesystemConfig",
                                    "config": {"allowed_roots": [str(allowed)]}}}}}))
    s.start()

    def _list(path):
        req = urllib.request.Request(
            f"http://127.0.0.1:{s.port}/invoke",
            data=json.dumps({"capability_id": "chp.adapters.filesystem.list_directory",
                             "payload": {"path": path}}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    try:
        # The provisioned config took effect: inside the allowed root works...
        assert _list(str(allowed))["outcome"] == "success"
        # ...and a path OUTSIDE the configured allowed_roots is refused.
        assert _list("/etc")["outcome"] != "success"
    finally:
        s.stop()


def test_removing_attachment_fails_host_profile_closed(tmp_path):
    from chp_server import Server, ServerConfig

    s = Server(ServerConfig(port=0, profile="host", store=str(tmp_path / "e.sqlite")))
    with pytest.raises(RuntimeError, match="fail-closed"):
        s.start()


def _member_host(tmp_path, name):
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

    host = LocalCapabilityHost(name, store=SQLiteEvidenceStore(str(tmp_path / f"{name}.sqlite")))

    async def ping(_ctx, payload):
        return {"pong": name, "text": payload.get("text")}

    host.register(CapabilityDescriptor(id=f"{name}.ping", version="1.0.0",
                                       description="Ping."), ping)
    return host


def test_router_gateway_profile(tmp_path):
    """Gateway: merged catalog + remote routing; local execution truthfully absent."""
    import json
    import urllib.request

    from chp_core.transport import LocalTransport
    from chp_host.server_port import RouterPort
    from chp_server import Server, ServerConfig

    transports = [LocalTransport(_member_host(tmp_path, n)) for n in ("m1", "m2")]
    s = Server(ServerConfig(port=0, profile="gateway", store=str(tmp_path / "g.sqlite")))
    s.attach(RouterPort(transports=transports, host_id="test-gateway"))
    s.start()
    try:
        assert s.ready()["ready"] is True
        by_name = {f.feature: f.state for f in s.features.snapshot(lifecycle=s.state)}
        assert by_name["federation"] == "ready"
        assert by_name["invocation.remote"] == "ready"
        assert by_name["capability.discovery"] == "ready"
        # Gateway MUST NOT imply local execution (PROFILE-007).
        assert by_name["invocation.local"] == "unsupported"
        # The merged catalog and remote attribution work through the wire.
        req = urllib.request.Request(
            f"http://127.0.0.1:{s.port}/invoke",
            data=json.dumps({"capability_id": "m2.ping", "payload": {"text": "hi"}}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            out = json.loads(r.read())
        assert out["outcome"] == "success" and out["data"]["pong"] == "m2"
    finally:
        s.stop()


def test_router_port_requires_remotes():
    from chp_host.server_port import RouterPort

    with pytest.raises(ValueError, match="remotes"):
        RouterPort().validate()


def test_mcp_export_attachment(tmp_path):
    """mcp.export truth: SSE bridge actually serving (auth-checked), import stays unsupported."""
    pytest.importorskip("mcp")
    import socket
    import time
    import urllib.error
    import urllib.request

    from chp_host.server_port import McpExportPort
    from chp_server import Server, ServerConfig

    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        mcp_port = sk.getsockname()[1]

    s = Server(ServerConfig(port=0, profile="host", store=str(tmp_path / "e.sqlite"),
                            attachments={"adapter_host": {
                                "adapters": ["memory"], "store": str(tmp_path / "h.sqlite")}}))
    s.attach(McpExportPort(port=mcp_port, api_key="sekrit"))
    s.start()
    try:
        by_name = {f.feature: f.state for f in s.features.snapshot(lifecycle=s.state)}
        assert by_name["mcp.export"] == "ready"
        assert by_name["mcp.import"] == "unsupported"  # no import bridge exists
        # The bridge is real: unauthenticated /sse is refused with 401.
        deadline = time.time() + 10
        while True:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{mcp_port}/sse", timeout=2)
                raise AssertionError("unauthenticated /sse unexpectedly succeeded")
            except urllib.error.HTTPError as e:
                assert e.code == 401
                break
            except (urllib.error.URLError, TimeoutError):
                if time.time() > deadline:
                    raise
                time.sleep(0.2)
    finally:
        s.stop()


def test_mcp_export_without_mcp_extra_fails_loudly(monkeypatch, tmp_path):
    import builtins

    from chp_host.server_port import McpExportPort

    real_import = builtins.__import__

    def no_mcp(name, *a, **kw):
        if name == "mcp" or name.startswith("mcp."):
            raise ImportError("No module named 'mcp'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_mcp)
    with pytest.raises(RuntimeError, match=r"chp-host\[mcp\]"):
        McpExportPort().validate()
