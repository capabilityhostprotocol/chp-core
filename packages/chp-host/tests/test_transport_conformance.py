"""Transport conformance: LocalTransport and HttpTransport behave equivalently."""

from __future__ import annotations

import pytest

from chp_core import HttpTransport, LocalTransport, Transport
from chp_core.types import CorrelationContext, InvocationEnvelope

from ._util import make_math_host, served


def _envelope(a: float, b: float, correlation_id: str | None = None) -> InvocationEnvelope:
    kwargs: dict = {"capability_id": "math.add", "payload": {"a": a, "b": b}}
    if correlation_id:
        kwargs["correlation"] = CorrelationContext(correlation_id=correlation_id)
    return InvocationEnvelope(**kwargs)


class TestProtocol:
    def test_local_satisfies_transport(self):
        assert isinstance(LocalTransport(make_math_host()), Transport)

    def test_http_satisfies_transport(self):
        assert isinstance(HttpTransport("http://127.0.0.1:1"), Transport)

    def test_local_transport_name_defaults_to_host_id(self):
        assert LocalTransport(make_math_host("xyz")).name == "xyz"

    def test_explicit_name_wins(self):
        assert LocalTransport(make_math_host(), name="n").name == "n"


class TestLocalTransport:
    @pytest.mark.asyncio
    async def test_invoke(self):
        tr = LocalTransport(make_math_host())
        result = await tr.ainvoke_envelope(_envelope(2, 3))
        assert result.outcome == "success"
        assert result.data["sum"] == 5

    @pytest.mark.asyncio
    async def test_discover(self):
        tr = LocalTransport(make_math_host())
        ids = [c["id"] for c in (await tr.discover())["capabilities"]]
        assert ids == ["math.add"]

    @pytest.mark.asyncio
    async def test_health(self):
        tr = LocalTransport(make_math_host())
        health = await tr.health()
        assert health["status"] == "ok"
        assert health["capability_count"] == 1

    @pytest.mark.asyncio
    async def test_replay(self):
        tr = LocalTransport(make_math_host())
        await tr.ainvoke_envelope(_envelope(1, 1, correlation_id="c-1"))
        replay = await tr.replay_result("c-1")
        assert len(replay["events"]) >= 2

    def test_supports_is_false_by_default(self):
        assert LocalTransport(make_math_host()).supports("streaming") is False


class TestHttpTransport:
    @pytest.mark.asyncio
    async def test_invoke(self):
        with served(make_math_host()) as url:
            tr = HttpTransport(url)
            result = await tr.ainvoke_envelope(_envelope(10, 5))
            assert result.outcome == "success"
            assert result.data["sum"] == 15

    @pytest.mark.asyncio
    async def test_discover(self):
        with served(make_math_host()) as url:
            tr = HttpTransport(url)
            ids = [c["id"] for c in (await tr.discover())["capabilities"]]
            assert ids == ["math.add"]

    @pytest.mark.asyncio
    async def test_health(self):
        with served(make_math_host()) as url:
            tr = HttpTransport(url)
            health = await tr.health()
            assert health["status"] == "ok"
            # capability_count is NOT disclosed on the unauthenticated /health
            # (moved to the authed /host descriptor) — mesh-count privacy.
            assert "capability_count" not in health

    @pytest.mark.asyncio
    async def test_replay(self):
        with served(make_math_host()) as url:
            tr = HttpTransport(url)
            res = await tr.ainvoke_envelope(_envelope(1, 1, correlation_id="c-http"))
            replay = await tr.replay_result(res.correlation.correlation_id)
            assert len(replay["events"]) >= 2

    @pytest.mark.asyncio
    async def test_dead_host_health_raises_connection_error(self):
        tr = HttpTransport("http://127.0.0.1:1")
        with pytest.raises(ConnectionError):
            await tr.health()

    @pytest.mark.asyncio
    async def test_dead_host_invoke_raises_connection_error(self):
        tr = HttpTransport("http://127.0.0.1:1")
        with pytest.raises(ConnectionError):
            await tr.ainvoke_envelope(_envelope(1, 2))


class TestEquivalence:
    @pytest.mark.asyncio
    async def test_local_and_http_agree(self):
        local = LocalTransport(make_math_host())
        with served(make_math_host()) as url:
            http = HttpTransport(url)
            lr = await local.ainvoke_envelope(_envelope(7, 8))
            hr = await http.ainvoke_envelope(_envelope(7, 8))
            assert lr.outcome == hr.outcome == "success"
            assert lr.data == hr.data == {"sum": 15}
