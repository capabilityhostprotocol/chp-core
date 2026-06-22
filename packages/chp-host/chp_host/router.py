"""MultiHostRouter — route capability invocations across several CHP hosts.

A router is built from an ordered list of ``Transport`` objects (in-process or
remote, in priority order). On :meth:`connect` it discovers each host's catalog
and builds a ``capability_id -> [transport]`` routing table. :meth:`ainvoke`
resolves the owning host(s) for a capability and dispatches to the first healthy
one, failing over on connection errors and propagating a shared correlation so
evidence can be stitched across hosts.

Design choices (see plan):
* **Priority**: insertion order of transports == priority; first-healthy-wins.
* **Round-robin**: opt-in (``selection="round_robin"``) to spread load across
  hosts that expose the same capability.
* **Failover**: a ``ConnectionError`` marks a host unhealthy (skipped until a
  recheck window elapses) and the router tries the next owner.
* **Federated evidence**: each host keeps its own append-only store; the router
  never moves evidence — :meth:`replay` fans out and merges into one timeline.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Iterable, Literal

from chp_core.transport import Transport
from chp_core.types import (
    CorrelationContext,
    InvocationEnvelope,
    InvocationResult,
    JSON,
    ReplayQuery,
    ReplayResult,
)

Selection = Literal["first", "round_robin"]


class UnknownCapabilityError(KeyError):
    """No connected host exposes the requested capability."""


class NoHealthyHostError(ConnectionError):
    """Every host that owns the capability is currently unreachable."""


def _normalize_correlation(correlation: CorrelationContext | JSON | None) -> CorrelationContext:
    if isinstance(correlation, CorrelationContext):
        return correlation
    if correlation:
        return CorrelationContext.from_mapping(correlation)
    return CorrelationContext()


class MultiHostRouter:
    """Route invocations across a pool of CHP hosts on the ``Transport`` seam."""

    def __init__(
        self,
        transports: Iterable[Transport],
        *,
        selection: Selection = "first",
        recheck_interval: float = 30.0,
    ) -> None:
        self._transports: list[Transport] = list(transports)
        self._selection: Selection = selection
        self._recheck_interval = recheck_interval
        # capability_id -> transports that serve it, in priority order
        self._routes: dict[str, list[Transport]] = {}
        # transport.name -> host descriptor (from discover)
        self._descriptors: dict[str, JSON] = {}
        # transport.name -> monotonic time after which to retry an unhealthy host
        self._unhealthy: dict[str, float] = {}
        # capability_id -> rotation index for round-robin
        self._rr: dict[str, int] = {}

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def connect(self) -> "MultiHostRouter":
        """Discover every host and (re)build the routing table.

        Hosts that fail to respond are marked unhealthy and skipped; the router
        still comes up with whatever hosts answered.
        """
        self._routes.clear()
        self._descriptors.clear()
        for tr in self._transports:
            try:
                descriptor = await tr.discover()
            except ConnectionError as exc:
                # Surface *which* node was dropped and why — a silent skip here
                # is how a wrong api_key or an unreachable peer goes unnoticed.
                print(f"  WARNING: skipped {tr.name}: {exc}", file=sys.stderr)
                self._mark_unhealthy(tr)
                continue
            self._mark_healthy(tr)
            self._descriptors[tr.name] = descriptor
            for cap in descriptor.get("capabilities", []):
                cid = cap.get("id")
                if not cid:
                    continue
                owners = self._routes.setdefault(cid, [])
                if tr not in owners:
                    owners.append(tr)
        return self

    # ── invocation ─────────────────────────────────────────────────────────────

    async def ainvoke(
        self,
        capability_id: str,
        payload: JSON | None = None,
        *,
        version: str | None = None,
        correlation: CorrelationContext | JSON | None = None,
        subject: JSON | None = None,
        mode: str = "sync",
        metadata: JSON | None = None,
    ) -> InvocationResult:
        """Route an invocation to a host that owns *capability_id*.

        Tries healthy owners in priority (or round-robin) order, failing over on
        ``ConnectionError``. The same correlation is propagated to whichever host
        runs, so :meth:`replay` can stitch the cross-host timeline.
        """
        owners = self._routes.get(capability_id)
        if not owners:
            raise UnknownCapabilityError(capability_id)

        corr = _normalize_correlation(correlation)
        candidates = self._ordered_candidates(capability_id, owners)

        last_error: Exception | None = None
        for tr in candidates:
            envelope = InvocationEnvelope(
                capability_id=capability_id,
                payload=payload or {},
                version=version,
                mode=mode,
                correlation=corr,
                subject=subject or {"id": "router", "type": "system"},
                metadata={**(metadata or {}), "routed_via": tr.name},
            )
            try:
                result = await tr.ainvoke_envelope(envelope)
            except ConnectionError as exc:
                last_error = exc
                self._mark_unhealthy(tr)
                continue
            self._mark_healthy(tr)
            return result

        raise NoHealthyHostError(
            f"no healthy host for capability {capability_id!r}"
        ) from last_error

    # ── discovery / introspection ───────────────────────────────────────────────

    async def discover(self) -> JSON:
        """Return a merged capability catalog across all connected hosts.

        Capabilities are deduped by ``capability_uri`` and annotated with the
        ``hosts`` (transport names) that serve them.
        """
        merged: dict[str, JSON] = {}
        for name, descriptor in self._descriptors.items():
            for cap in descriptor.get("capabilities", []):
                uri = cap.get("capability_uri") or f"{cap.get('id')}:{cap.get('version')}"
                entry = merged.get(uri)
                if entry is None:
                    entry = {**cap, "hosts": []}
                    merged[uri] = entry
                if name not in entry["hosts"]:
                    entry["hosts"].append(name)
        return {
            "kind": "multi-host",
            "hosts": list(self._descriptors.keys()),
            "capabilities": list(merged.values()),
            "capability_count": len(merged),
        }

    def hosts_for(self, capability_id: str) -> list[str]:
        """Return the names of hosts that own *capability_id*, in priority order."""
        return [tr.name for tr in self._routes.get(capability_id, [])]

    @property
    def capability_ids(self) -> list[str]:
        """All capability ids reachable through the router."""
        return sorted(self._routes.keys())

    # ── evidence ────────────────────────────────────────────────────────────────

    async def replay(self, correlation_id: str) -> list[JSON]:
        """Fan out replay to every host and merge into one ordered timeline.

        Evidence is never centralized — each host keeps its own append-only,
        hash-chained store. Each returned event is tagged with ``_host`` so the
        stitched view stays attributable.
        """
        events: list[JSON] = []
        for tr in self._transports:
            if not self._is_healthy(tr):
                continue
            try:
                result = await tr.replay_result(correlation_id)
            except ConnectionError:
                self._mark_unhealthy(tr)
                continue
            for event in result.get("events", []):
                events.append({**event, "_host": tr.name})
        events.sort(key=lambda e: (e.get("timestamp", ""), e.get("sequence", 0)))
        return events

    async def ainvoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        """Route a pre-built envelope through the routing table.

        Delegates to :meth:`ainvoke` so priority, failover, and round-robin
        selection all apply. Enables ``serve_http(router)`` by satisfying the
        same duck-type surface as ``LocalCapabilityHost``.
        """
        if isinstance(envelope, dict):
            envelope = InvocationEnvelope.from_mapping(envelope)
        return await self.ainvoke(
            envelope.capability_id,
            envelope.payload,
            version=envelope.version,
            correlation=envelope.correlation,
            subject=envelope.subject,
            mode=envelope.mode,
            metadata=envelope.metadata,
        )

    def replay_result(self, query: str | ReplayQuery | JSON) -> ReplayResult:
        """Fan out replay across all hosts and return a merged :class:`ReplayResult`.

        Called synchronously from ``ThreadingHTTPServer`` worker threads (no
        running event loop), so ``asyncio.run`` is safe here — the same pattern
        the HTTP handler already uses for ``ainvoke_envelope``.
        """
        if isinstance(query, str):
            correlation_id = query
        elif isinstance(query, dict):
            correlation_id = str(query.get("correlation_id", ""))
        else:
            correlation_id = query.correlation_id
        events = asyncio.run(self.replay(correlation_id))
        return ReplayResult(
            correlation_id=correlation_id,
            events=events,
            event_count=len(events),
        )

    async def health(self) -> JSON:
        """Probe every host; return an aggregate health snapshot."""
        hosts: list[JSON] = []
        for tr in self._transports:
            try:
                snapshot = await tr.health()
            except ConnectionError as exc:
                self._mark_unhealthy(tr)
                hosts.append({"name": tr.name, "healthy": False, "error": str(exc)})
                continue
            self._mark_healthy(tr)
            hosts.append({"name": tr.name, "healthy": True, **snapshot})
        healthy = sum(1 for h in hosts if h["healthy"])
        return {
            "status": "ok" if healthy == len(hosts) else ("degraded" if healthy else "down"),
            "host_count": len(hosts),
            "healthy_count": healthy,
            "hosts": hosts,
        }

    # ── health bookkeeping ──────────────────────────────────────────────────────

    def _ordered_candidates(
        self, capability_id: str, owners: list[Transport]
    ) -> list[Transport]:
        # Routing-strategy seam: this is where capability invocations are ordered
        # across the nodes that own them. Today: "first" (priority/insertion
        # order) and "round_robin" (load spread). Future distributed-app
        # strategies — capacity-aware, locality-aware, or explicit node-pinning —
        # plug in here by reordering `healthy` based on additional signals
        # (node load, region, a pin map). The strategy name comes from the
        # gateway's `selection` config (mesh.json → gateway.selection).
        healthy = [tr for tr in owners if self._is_healthy(tr)]
        unhealthy = [tr for tr in owners if not self._is_healthy(tr)]
        if self._selection == "round_robin" and len(healthy) > 1:
            idx = self._rr.get(capability_id, 0) % len(healthy)
            self._rr[capability_id] = idx + 1
            healthy = healthy[idx:] + healthy[:idx]
        # Healthy owners first; unhealthy kept as a last resort (they may have recovered).
        return healthy + unhealthy

    def _is_healthy(self, tr: Transport) -> bool:
        until = self._unhealthy.get(tr.name)
        if until is None:
            return True
        if time.monotonic() >= until:
            # Recheck window elapsed — optimistically allow another attempt.
            del self._unhealthy[tr.name]
            return True
        return False

    def _mark_unhealthy(self, tr: Transport) -> None:
        self._unhealthy[tr.name] = time.monotonic() + self._recheck_interval

    def _mark_healthy(self, tr: Transport) -> None:
        self._unhealthy.pop(tr.name, None)
