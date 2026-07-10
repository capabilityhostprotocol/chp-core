"""Integration tests: MultiHostRouter served over CHP HTTP (gateway mode)."""

from __future__ import annotations

import json
import threading
import time
import urllib.request

import pytest

from chp_core import LocalTransport, create_http_server
from chp_host import MultiHostRouter

from ._util import make_echo_host, make_math_host


def _start_router_server(*hosts, **router_kwargs):
    """Connect a router over LocalTransports and serve it on an ephemeral port."""
    import asyncio
    transports = [LocalTransport(h, name=h.host_id) for h in hosts]
    router = MultiHostRouter(transports, **router_kwargs)
    asyncio.run(router.connect())
    server = create_http_server(router, bind="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    return server, f"http://127.0.0.1:{port}"


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post(url: str, body: dict) -> dict:
    raw = json.dumps(body).encode()
    req = urllib.request.Request(url, data=raw, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


class TestGatewayHTTP:
    def setup_method(self):
        self.server, self.base = _start_router_server(
            make_echo_host("mac", "mac", cap_id="echo.who"),
            make_math_host("math-host"),
        )

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_health_returns_ok(self):
        data = _get(f"{self.base}/health")
        assert data["status"] == "ok"
        assert data["protocol"] == "chp"
        # capability_count is disclosed on the authed /host, not public /health.
        assert "capability_count" not in data

    def test_capabilities_lists_all_hosts(self):
        data = _get(f"{self.base}/capabilities")
        ids = {c["id"] for c in data["capabilities"]}
        assert "echo.who" in ids
        assert "math.add" in ids

    def test_host_returns_multi_host_descriptor(self):
        data = _get(f"{self.base}/host")
        assert data["kind"] == "multi-host"
        assert len(data["hosts"]) == 2
        assert data["capability_count"] >= 2

    def test_invoke_routes_to_correct_host(self):
        result = _post(f"{self.base}/invoke", {"capability_id": "echo.who", "payload": {}})
        assert result["outcome"] == "success"
        assert result["data"] == {"host": "mac"}

    def test_invoke_math_capability(self):
        result = _post(
            f"{self.base}/invoke",
            {"capability_id": "math.add", "payload": {"a": 7, "b": 3}},
        )
        assert result["outcome"] == "success"
        assert result["data"]["sum"] == 10

    def test_replay_by_path_returns_events(self):
        inv = _post(f"{self.base}/invoke", {"capability_id": "math.add", "payload": {"a": 1, "b": 1}})
        corr_id = inv["correlation"]["correlation_id"]
        replay = _get(f"{self.base}/replay/{corr_id}")
        assert replay["event_count"] >= 2
        # Events are tagged with _host
        for event in replay["events"]:
            assert "_host" in event

    def test_verify_returns_note_not_error(self):
        # Gateway has no local store — should return a structured note, not 500
        data = _get(f"{self.base}/verify/nonexistent-corr-id")
        assert "note" in data
        assert "hosts" in data

    def test_invoke_unknown_capability_is_processed_denial(self):
        # Spec §11: unknown mesh-wide is a PROCESSED denial — HTTP 200 with
        # outcome denied + capability_not_found (was a misleading 400 before
        # v0.2.4, because UnknownCapabilityError is a KeyError subclass).
        data = _post(f"{self.base}/invoke", {"capability_id": "no.such.cap", "payload": {}})
        assert data["outcome"] == "denied"
        assert data["denial"]["code"] == "capability_not_found"


class TestGatewayHealthHostId:
    """§1D: /health must report the gateway's own host_id, not an upstream URL."""

    def setup_method(self):
        self.server, self.base = _start_router_server(
            make_echo_host("mac", "mac", cap_id="echo.who"),
            make_math_host("math-host"),
            host_id="my-custom-gateway",
        )

    def teardown_method(self):
        self.server.shutdown()
        self.server.server_close()

    def test_health_returns_gateway_host_id(self):
        data = _get(f"{self.base}/health")
        assert data["host_id"] == "my-custom-gateway", (
            f"Expected gateway's own host_id, got: {data['host_id']!r}"
        )

    def test_health_host_id_not_upstream_url(self):
        """Regression: host_id must not be an upstream URL like 'http://127.0.0.1:8803'."""
        data = _get(f"{self.base}/health")
        host_id = data["host_id"]
        assert not host_id.startswith("http://"), (
            f"host_id should not be an upstream URL, got: {host_id!r}"
        )
