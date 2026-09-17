"""The client side of the Zenoh binding — ``ZenohTransport``."""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from chp_core.types import InvocationEnvelope, InvocationResult, JSON

from .keys import KEY_PREFIX, keys, presence_glob
from .presence import Presence
from .pubsub import Stream
from .session import open_session
from .wire import first_reply, result_from_dict


class ZenohTransport:
    """Client transport over Zenoh (satisfies ``chp_core.transport.Transport``).

    Every RPC call is a Zenoh ``get()`` against the host's queryable, run in a worker thread so the
    blocking Zenoh API never stalls the router's event loop — exactly how ``HttpTransport`` wraps
    ``urllib``. A ``ConnectionError`` (no reply) propagates unchanged so the router can fail over.
    Async event streams (evidence, decisions) and liveliness presence ride Zenoh pub/sub instead.
    """

    def __init__(self, host_id: str, *, session: Any = None, config: Any = None,
                 name: str | None = None, prefix: str = KEY_PREFIX,
                 timeout: float = 30.0) -> None:
        self.host_id = host_id
        self._k = keys(host_id, prefix=prefix)
        self._prefix = prefix
        self._session, self._owns = open_session(session, config)
        self._timeout = timeout
        self.name = name or f"zenoh://{host_id}"

    def _get(self, key: str, payload: JSON | None = None) -> JSON:
        import json
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if payload is not None:
            kwargs["payload"] = json.dumps(payload).encode()
        return first_reply(self._session.get(key, **kwargs))

    async def ainvoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        data = await asyncio.to_thread(self._get, self._k["invoke"], envelope.to_dict())
        return result_from_dict(data)

    async def discover(self) -> JSON:
        return await asyncio.to_thread(self._get, self._k["declarations"])

    async def replay_result(self, query: "str | JSON") -> JSON:
        q = {"correlation_id": query} if isinstance(query, str) else query
        return await asyncio.to_thread(self._get, self._k["replay"], q)

    async def export_bundle(self, correlation_id: str) -> JSON:
        """The host's SIGNED evidence bundle for ``correlation_id`` — the offline-verifiable
        denial evidence an approval ingests (mirrors HTTP ``export_bundle``; only the carrier
        differs). ``verify_bundle`` checks the hash chain, root hash, and host signature."""
        return await asyncio.to_thread(
            self._get, self._k["export"], {"correlation_id": correlation_id})

    async def health(self) -> JSON:
        return await asyncio.to_thread(self._get, self._k["health"])

    def supports(self, feature: str) -> bool:
        # Zenoh's native pub/sub + liveliness give streaming, evidence, async decisions, and
        # push-based presence — things the HTTP request/response binding cannot (§4).
        return feature in {"streaming", "evidence", "decisions", "presence"}

    def subscribe_evidence(self, callback: Callable[[JSON], None]) -> Any:
        """Subscribe to the host's evidence stream (§4). Returns the Zenoh subscriber (keep a
        reference; call ``.undeclare()`` to stop)."""
        return Stream(self._session, self._k["evidence"]).subscribe(callback)

    def subscribe_decisions(self, callback: Callable[[JSON], None]) -> Any:
        """Subscribe to the host's async HITL decision stream — each ``{approval_id, decision, by}``
        as it is published, no blocking query. Returns the Zenoh subscriber."""
        return Stream(self._session, self._k["decisions"]).subscribe(callback)

    def watch_presence(self, on_change: Callable[[str, bool], None], *,
                       key_expr: str | None = None, history: bool = True) -> Any:
        """Watch host liveliness — ``on_change(host_key, alive)`` the instant a host comes up or drops.
        Defaults to the whole-fleet presence glob. Returns the Zenoh liveliness subscriber."""
        return Presence(self._session).watch(
            key_expr or presence_glob(self._prefix), on_change, history=history)

    def live_hosts(self, *, key_expr: str | None = None, timeout: float = 5.0) -> list[str]:
        """The presence keys currently live (a one-shot liveliness query over the fleet glob)."""
        return Presence(self._session).query(key_expr or presence_glob(self._prefix), timeout=timeout)

    def close(self) -> None:
        if self._owns:
            self._session.close()
