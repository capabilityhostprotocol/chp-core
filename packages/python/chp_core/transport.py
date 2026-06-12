"""Transport seam for CHP hosts.

A ``Transport`` is the uniform async surface a client uses to talk to *one* host —
whether that host is in-process (`LocalTransport`) or reached over a wire
(`HttpTransport`, and later Zenoh/gRPC). The router in ``chp-host`` composes a
list of transports into a multi-host pool.

The contract is deliberately thin — request/response plus discovery, replay, and
health — so new transports are cheap to add. Streaming / evidence pub-sub are
*optional* extensions advertised via ``supports(feature)`` and an optional
``subscribe_evidence`` hook, so adding them later (e.g. for a Zenoh mesh) never
breaks the core contract.

This module depends only on the stdlib + chp-core internals: no transport here
pulls a third-party dependency. Heavier transports (Zenoh, gRPC) live in
downstream packages and implement this same ``Transport`` protocol.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from .host import LocalCapabilityHost
from .http import RemoteCapabilityHost
from .types import InvocationEnvelope, InvocationResult, JSON, ReplayQuery


@runtime_checkable
class Transport(Protocol):
    """Uniform async surface for talking to a single CHP host.

    Implementations: :class:`LocalTransport` (in-process),
    :class:`HttpTransport` (stdlib HTTP). Downstream packages may add others
    (Zenoh, gRPC) by satisfying this same protocol.
    """

    name: str

    async def ainvoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        """Invoke a capability from a pre-built envelope and return its result."""
        ...

    async def discover(self) -> JSON:
        """Return the host descriptor (id, capabilities, evidence policy, ...)."""
        ...

    async def replay_result(self, query: "str | ReplayQuery | JSON") -> JSON:
        """Return a replay result (as a dict) for a correlation id or query."""
        ...

    async def health(self) -> JSON:
        """Return a health snapshot: status, host_id, protocol, capability_count."""
        ...

    def supports(self, feature: str) -> bool:
        """Report whether an optional feature (e.g. ``"streaming"``) is available."""
        ...


def _health_from_descriptor(descriptor: JSON) -> JSON:
    """Build a /health-shaped snapshot from a host descriptor."""
    return {
        "status": "ok",
        "host_id": descriptor.get("id", "unknown"),
        "protocol": "chp",
        "version": "0.1",
        "capability_count": len(descriptor.get("capabilities", [])),
    }


class LocalTransport:
    """Transport over an in-process :class:`LocalCapabilityHost`.

    Lets a local host participate in a multi-host router alongside remote hosts
    on exactly the same seam. Invocation is awaited directly; the synchronous
    discover/replay calls are fast in-memory operations.
    """

    def __init__(self, host: LocalCapabilityHost, *, name: str | None = None) -> None:
        self._host = host
        self.name = name or host.host_id

    async def ainvoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        return await self._host.ainvoke_envelope(envelope)

    async def discover(self) -> JSON:
        return self._host.discover()

    async def replay_result(self, query: "str | ReplayQuery | JSON") -> JSON:
        return self._host.replay_result(query).to_dict()

    async def health(self) -> JSON:
        return _health_from_descriptor(self._host.discover())

    def supports(self, feature: str) -> bool:
        return False


class HttpTransport:
    """Transport over CHP's stdlib HTTP surface.

    Wraps :class:`RemoteCapabilityHost` (blocking ``urllib``) and runs each call
    in a worker thread so it never blocks the router's event loop. A
    ``ConnectionError`` from the underlying client propagates unchanged so the
    router can fail over to another host.
    """

    def __init__(
        self,
        base_url: str,
        *,
        name: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._remote = RemoteCapabilityHost(base_url, timeout=timeout)
        self.name = name or base_url.rstrip("/")

    async def ainvoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        return await asyncio.to_thread(self._remote.invoke_envelope, envelope)

    async def discover(self) -> JSON:
        return await asyncio.to_thread(self._remote.discover)

    async def replay_result(self, query: "str | ReplayQuery | JSON") -> JSON:
        return await asyncio.to_thread(self._remote.replay_result, query)

    async def health(self) -> JSON:
        return await asyncio.to_thread(self._remote.health)

    def supports(self, feature: str) -> bool:
        return False
