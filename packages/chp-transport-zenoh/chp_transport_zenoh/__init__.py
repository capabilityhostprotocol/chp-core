"""CHP over Zenoh — a non-HTTP transport binding (spec/chp-zenoh-binding.md).

A ``ZenohTransport`` satisfies the same ``chp_core.transport.Transport`` protocol as
the HTTP transport, so the router composes it with zero changes; a ``ZenohHostServer``
serves a ``LocalCapabilityHost`` over Zenoh query/reply. The wire OBJECTS are
unchanged — the same ``InvocationEnvelope`` / ``InvocationResult`` JSON the HTTP binding
carries — only the CARRIER differs (Zenoh key-expression query/reply + evidence
pub/sub). This package pulls the heavy ``eclipse-zenoh`` dependency so ``chp-core``
stays dependency-free.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

from chp_core.types import (CorrelationContext, InvocationEnvelope,
                            InvocationResult, JSON)

__all__ = ["KEY_PREFIX", "keys", "ZenohTransport", "ZenohHostServer",
           "result_from_dict"]

KEY_PREFIX = "chp/v1"


def keys(host_id: str, *, prefix: str = KEY_PREFIX) -> dict[str, str]:
    """The Zenoh key-expression table for a host (chp-zenoh-binding.md §2)."""
    return {
        "invoke": f"{prefix}/invocations/{host_id}/requests",
        "declarations": f"{prefix}/capabilities/{host_id}/declarations",
        "replay": f"{prefix}/replay/{host_id}/requests",
        "health": f"{prefix}/health/{host_id}",
        "evidence": f"{prefix}/evidence/{host_id}/stream",
    }


def result_from_dict(data: JSON) -> InvocationResult:
    """Reconstruct an ``InvocationResult`` from its wire dict (mirrors the HTTP
    client's deserialization — the same object, a different carrier)."""
    from chp_core.types import DenialReason

    denial_raw = data.get("denial")
    denial = (DenialReason(
        code=str(denial_raw.get("code", "")),
        message=str(denial_raw.get("message", "")),
        retryable=bool(denial_raw.get("retryable", False)),
        details=dict(denial_raw.get("details") or {}),
    ) if denial_raw else None)
    return InvocationResult(
        invocation_id=str(data.get("invocation_id", "")),
        capability_id=str(data.get("capability_id", "")),
        capability_version=data.get("capability_version"),
        correlation=CorrelationContext.from_mapping(data.get("correlation")),
        outcome=data.get("outcome", "failure"),  # type: ignore[arg-type]
        success=bool(data.get("success", False)),
        data=data.get("data"),
        error=data.get("error"),
        denial=denial,
        evidence_ids=list(data.get("evidence_ids") or []),
        started_at=data.get("started_at"),
        completed_at=data.get("completed_at", ""),
    )


def _first_reply(replies: Any) -> JSON:
    """Drain a Zenoh get() and return the first OK reply's JSON payload."""
    for reply in replies:
        ok = getattr(reply, "ok", None)
        if ok is not None:
            return json.loads(bytes(ok.payload))
    raise ConnectionError("no Zenoh reply (queryable unreachable or errored)")


def _open_session(session: Any, config: Any) -> tuple[Any, bool]:
    """Return (session, owns_it). A caller MAY pass an existing session (shared
    across transports); else open one from ``config`` (default peer)."""
    if session is not None:
        return session, False
    import zenoh
    return zenoh.open(config if config is not None else zenoh.Config()), True


class ZenohTransport:
    """Client transport over Zenoh (satisfies ``chp_core.transport.Transport``).

    Every call is a Zenoh ``get()`` against the host's queryable, run in a worker
    thread so the blocking Zenoh API never stalls the router's event loop —
    exactly how ``HttpTransport`` wraps ``urllib``. A ``ConnectionError`` (no reply)
    propagates unchanged so the router can fail over.
    """

    def __init__(self, host_id: str, *, session: Any = None, config: Any = None,
                 name: str | None = None, prefix: str = KEY_PREFIX,
                 timeout: float = 30.0) -> None:
        self.host_id = host_id
        self._k = keys(host_id, prefix=prefix)
        self._session, self._owns = _open_session(session, config)
        self._timeout = timeout
        self.name = name or f"zenoh://{host_id}"

    def _get(self, key: str, payload: JSON | None = None) -> JSON:
        import zenoh  # noqa: F401  (ensures the dep is importable)
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if payload is not None:
            kwargs["payload"] = json.dumps(payload).encode()
        return _first_reply(self._session.get(key, **kwargs))

    async def ainvoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        data = await asyncio.to_thread(self._get, self._k["invoke"], envelope.to_dict())
        return result_from_dict(data)

    async def discover(self) -> JSON:
        return await asyncio.to_thread(self._get, self._k["declarations"])

    async def replay_result(self, query: "str | JSON") -> JSON:
        q = {"correlation_id": query} if isinstance(query, str) else query
        return await asyncio.to_thread(self._get, self._k["replay"], q)

    async def health(self) -> JSON:
        return await asyncio.to_thread(self._get, self._k["health"])

    def supports(self, feature: str) -> bool:
        # Zenoh's native pub/sub gives evidence streaming HTTP can't (§4).
        return feature in {"streaming", "evidence"}

    def subscribe_evidence(self, callback: Callable[[JSON], None]) -> Any:
        """Subscribe to the host's evidence stream (§4). Returns the Zenoh
        subscriber (keep a reference; call ``.undeclare()`` to stop)."""
        def _on_sample(sample: Any) -> None:
            callback(json.loads(bytes(sample.payload)))
        return self._session.declare_subscriber(self._k["evidence"], _on_sample)

    def close(self) -> None:
        if self._owns:
            self._session.close()


class ZenohHostServer:
    """Serve a ``LocalCapabilityHost`` over Zenoh — the queryable side of the
    binding. Declares queryables for invoke / discover / replay / health and
    publishes each handled invocation's completed evidence to the evidence stream.
    """

    def __init__(self, host: Any, *, session: Any = None, config: Any = None,
                 host_id: str | None = None, prefix: str = KEY_PREFIX) -> None:
        self._host = host
        self.host_id = host_id or getattr(host, "host_id", "local-chp-host")
        self._k = keys(self.host_id, prefix=prefix)
        self._session, self._owns = _open_session(session, config)
        self._queryables = [
            self._session.declare_queryable(self._k["invoke"], self._on_invoke),
            self._session.declare_queryable(self._k["declarations"], self._on_discover),
            self._session.declare_queryable(self._k["replay"], self._on_replay),
            self._session.declare_queryable(self._k["health"], self._on_health),
        ]

    # ── queryable handlers (each replies with a wire JSON object) ──────────────

    def _reply(self, query: Any, key: str, obj: JSON) -> None:
        query.reply(key, json.dumps(obj).encode())

    def _on_invoke(self, query: Any) -> None:
        env = InvocationEnvelope.from_mapping(json.loads(bytes(query.payload)))
        result = asyncio.run(self._host.ainvoke_envelope(env))
        self._reply(query, self._k["invoke"], result.to_dict())
        # Native evidence pub/sub (§4): broadcast this invocation's completed
        # evidence — something the HTTP binding's request/response cannot do.
        for ev in self._host.replay(env.correlation.correlation_id):
            if ev.get("event_type") == "execution_completed":
                self._session.put(self._k["evidence"], json.dumps(ev).encode())

    def _on_discover(self, query: Any) -> None:
        desc = self._host.discover()
        self._reply(query, self._k["declarations"],
                    asyncio.run(desc) if asyncio.iscoroutine(desc) else desc)

    def _on_replay(self, query: Any) -> None:
        q = json.loads(bytes(query.payload)) if query.payload else {}
        corr = q.get("correlation_id", "")
        self._reply(query, self._k["replay"], {"events": self._host.replay(corr)})

    def _on_health(self, query: Any) -> None:
        desc = self._host.discover()
        desc = asyncio.run(desc) if asyncio.iscoroutine(desc) else desc
        self._reply(query, self._k["health"], {
            "status": "ok", "host_id": self.host_id, "protocol": "chp",
            "capability_count": len(desc.get("capabilities", [])),
        })

    def close(self) -> None:
        for q in self._queryables:
            try:
                q.undeclare()
            except Exception:  # noqa: BLE001
                pass
        if self._owns:
            self._session.close()
