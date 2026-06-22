"""End-to-end mesh tests over real HTTP transports + auth.

These guard the exact regressions that were hand-debugged on live machines
during the two-Mac bootstrap, so they can never silently come back:

  1. Capabilities route to the owning node across the HTTP transport (not just
     the in-process ``LocalTransport`` path covered by ``test_gateway.py``).
  2. ``/health`` is public — reachable with no ``X-CHP-Key`` — so mesh probes
     and ``mesh add`` can see a node before holding its key.
  3. Authed endpoints (``/host``, ``/invoke``) stay gated: 401 without the key,
     200 with it.
  4. A wrong ``api_key`` makes the router *skip* that transport (401 raised as
     ``ConnectionError``) instead of crashing the whole gateway.

Auth is keyed off the process-global ``CHP_HOST_API_KEY`` env var, exactly as a
real host reads it (injected from the keychain at startup). ``monkeypatch`` sets
and auto-restores it per test.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

import pytest

from chp_core import HttpTransport
from chp_host import MultiHostRouter

from ._util import make_echo_host, make_math_host, served

CORRECT_KEY = "test-mesh-key-correct"
WRONG_KEY = "test-mesh-key-wrong"


def _get(url: str, key: str | None = None):
    req = urllib.request.Request(url)
    if key:
        req.add_header("X-CHP-Key", key)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def _post(url: str, body: dict, key: str | None = None):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    if key:
        req.add_header("X-CHP-Key", key)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


# ---------------------------------------------------------------------------
# 1. Cross-node routing over real HTTP transports
# ---------------------------------------------------------------------------

def test_cross_node_routing_over_http():
    """A router over two HTTP-served hosts routes each capability to its owner."""
    with served(make_echo_host("node-a", "node-a", cap_id="a.cap")) as url_a, \
         served(make_math_host("node-b")) as url_b:
        router = MultiHostRouter([
            HttpTransport(url_a, name="node-a"),
            HttpTransport(url_b, name="node-b"),
        ])
        asyncio.run(router.connect())

        merged = asyncio.run(router.discover())
        ids = {c["id"] for c in merged["capabilities"]}
        assert {"a.cap", "math.add"} <= ids

        # Each capability lands on the host that owns it.
        assert router.hosts_for("a.cap") == ["node-a"]
        assert router.hosts_for("math.add") == ["node-b"]

        echo = asyncio.run(router.ainvoke("a.cap", {}))
        assert echo.outcome == "success"
        assert echo.data == {"host": "node-a"}

        add = asyncio.run(router.ainvoke("math.add", {"a": 7, "b": 3}))
        assert add.outcome == "success"
        assert add.data["sum"] == 10


# ---------------------------------------------------------------------------
# 2. /health is public even when auth is configured
# ---------------------------------------------------------------------------

def test_health_is_public_with_auth_enabled(monkeypatch):
    """`/health` must answer 200 with no key — mesh probes depend on it."""
    monkeypatch.setenv("CHP_HOST_API_KEY", CORRECT_KEY)
    with served(make_math_host("guarded")) as url:
        status, body = _get(f"{url}/health")  # no key
        assert status == 200
        assert body["status"] == "ok"
        assert body["protocol"] == "chp"


# ---------------------------------------------------------------------------
# 3. Authed endpoints stay gated
# ---------------------------------------------------------------------------

def test_authed_endpoints_require_key(monkeypatch):
    monkeypatch.setenv("CHP_HOST_API_KEY", CORRECT_KEY)
    with served(make_math_host("guarded")) as url:
        # /host: 401 without key, 200 with it.
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(f"{url}/host")
        assert exc.value.code == 401

        status, host_desc = _get(f"{url}/host", key=CORRECT_KEY)
        assert status == 200
        assert any(c["id"] == "math.add" for c in host_desc["capabilities"])

        # /invoke: 401 without key, 200 with it.
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(f"{url}/invoke", {"capability_id": "math.add", "payload": {"a": 1, "b": 2}})
        assert exc.value.code == 401

        status, result = _post(
            f"{url}/invoke",
            {"capability_id": "math.add", "payload": {"a": 1, "b": 2}},
            key=CORRECT_KEY,
        )
        assert status == 200
        assert result["data"]["sum"] == 3


# ---------------------------------------------------------------------------
# 4. A wrong key skips the transport, never crashes the router
# ---------------------------------------------------------------------------

def test_wrong_key_skips_transport_without_crashing(monkeypatch, capsys):
    """One bad peer key must not take down the gateway — it gets skipped (and logged)."""
    monkeypatch.setenv("CHP_HOST_API_KEY", CORRECT_KEY)
    with served(make_echo_host("good", "good", cap_id="good.cap")) as url_good, \
         served(make_math_host("bad")) as url_bad:
        router = MultiHostRouter([
            HttpTransport(url_good, name="good", api_key=CORRECT_KEY),
            HttpTransport(url_bad, name="bad", api_key=WRONG_KEY),
        ])

        # connect() must not raise even though "bad" returns 401.
        asyncio.run(router.connect())

        merged = asyncio.run(router.discover())
        ids = {c["id"] for c in merged["capabilities"]}
        assert "good.cap" in ids          # healthy host came up
        assert "math.add" not in ids      # bad host was skipped, not fatal

        # The skip is logged so an operator can see which node was dropped (§1C).
        assert "skipped bad" in capsys.readouterr().err

        # The healthy host is still fully usable.
        echo = asyncio.run(router.ainvoke("good.cap", {}))
        assert echo.outcome == "success"
        assert echo.data == {"host": "good"}
