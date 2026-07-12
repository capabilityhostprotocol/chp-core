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
import os
import sys
import time
from typing import Iterable, Literal

from chp_core.transport import Transport
from chp_core.types import (
    CorrelationContext,
    DenialReason,
    ExecutionEvidence,
    InvocationEnvelope,
    InvocationResult,
    JSON,
    ReplayQuery,
    ReplayResult,
    new_id,
    utc_now,
)

Selection = Literal["first", "round_robin", "least_loaded"]

# Capabilities whose load is GPU-bound — routed by GPU utilization when stats exist.
_INFERENCE_HINTS = ("local_llm", "vllm", "tei", "huggingface", "sglang", "mlx")
_STATS_TTL = 15.0  # seconds a cached host.stats snapshot is considered fresh
# Seconds before the routing catalog (routes + per-host descriptors/schemas) is
# re-discovered on the next invoke, so a node restart/upgrade (new capabilities or
# changed input schemas) propagates WITHOUT a manual gateway reload. Override via
# CHP_ROUTER_CATALOG_TTL; set <=0 to disable auto-refresh.
_CATALOG_TTL = float(os.environ.get("CHP_ROUTER_CATALOG_TTL", "60") or 60)


class UnknownCapabilityError(KeyError):
    """No connected host exposes the requested capability.

    Since spec §11 (proposal 0003) :meth:`MultiHostRouter.ainvoke` no longer
    raises this — it returns a processed ``capability_not_found`` denial.
    Kept exported for API compatibility."""


class NoHealthyHostError(ConnectionError):
    """Every host that owns the capability is currently unreachable.

    Since spec §11 (proposal 0003) :meth:`MultiHostRouter.ainvoke` no longer
    raises this — it returns a processed ``host_unreachable`` denial.
    Kept exported for API compatibility."""


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
        breaker_threshold: int = 1,
        host_id: str = "chp-gateway",
        host_roles: dict[str, str] | None = None,
        store=None,
    ) -> None:
        self._transports: list[Transport] = list(transports)
        self._selection: Selection = selection
        self._recheck_interval = recheck_interval
        # Circuit breaker: consecutive failures before tripping unhealthy.
        # Default 1 = trip on the first failure — the §11 reference behavior
        # the conformance suites assert; production configs opt into higher
        # thresholds (gateway.breaker_threshold). A tripped host's recheck
        # window escalates x2 per repeat trip, capped at 8x.
        self._breaker_threshold = max(1, int(breaker_threshold))
        self._failure_counts: dict[str, int] = {}
        self._trip_counts: dict[str, int] = {}
        self._half_open_probe: dict[str, bool] = {}
        self._host_id: str = host_id
        # Optional evidence store (spec §11 posture): with one, routing denials
        # and health transitions land on the gateway's OWN chain and merge into
        # stitched replays. Public `.store` on purpose — /metrics duck-types it.
        # Storeless embedded routers stay conformant (returned-denial floor).
        self.store = store
        # transport.name -> role (worker/inference/nas/...), for affinity routing
        self._host_roles: dict[str, str] = dict(host_roles or {})
        # capability_id -> transports that serve it, in priority order
        self._routes: dict[str, list[Transport]] = {}
        # transport.name -> host descriptor (from discover)
        self._descriptors: dict[str, JSON] = {}
        # transport.name -> monotonic time after which to retry an unhealthy host
        self._unhealthy: dict[str, float] = {}
        # capability_id -> rotation index for round-robin
        self._rr: dict[str, int] = {}
        # transport.name -> (monotonic_ts, stats dict) for capacity-aware routing
        self._stats_cache: dict[str, tuple[float, JSON]] = {}
        # monotonic time of the last full catalog discovery (for TTL auto-refresh)
        self._last_discover: float = 0.0
        # guards the inline unknown-capability refresh against a stampede
        import threading as _threading
        self._refresh_lock = _threading.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def connect(self) -> "MultiHostRouter":
        """Discover every host and (re)build the routing table.

        Hosts that fail to respond are marked unhealthy and skipped; the router
        still comes up with whatever hosts answered. Discovery runs in PARALLEL
        with a per-probe timeout — one hung/DNS-stalled member must not stall
        cold start (or, via ``_refresh_catalog``, unrelated invokes) for its
        full transport timeout.
        """
        results = await self._discover_all()
        routes: dict[str, list[Transport]] = {}
        descriptors: dict[str, JSON] = {}
        for tr, outcome in results:
            if isinstance(outcome, BaseException):
                # Surface *which* node was dropped and why — a silent skip here
                # is how a wrong api_key or an unreachable peer goes unnoticed.
                print(f"  WARNING: skipped {tr.name}: {outcome}", file=sys.stderr)
                self._mark_unhealthy(tr)
                continue
            if outcome is None:  # identity-pin mismatch (already marked + warned)
                continue
            self._mark_healthy(tr)
            descriptors[tr.name] = outcome
            for cap in outcome.get("capabilities", []):
                cid = cap.get("id")
                if not cid:
                    continue
                owners = routes.setdefault(cid, [])
                if tr not in owners:
                    owners.append(tr)
        # Swap whole dicts (atomic ref assignment) — handler threads read a
        # consistent snapshot; never mutate the live tables in place.
        self._routes = routes
        self._descriptors = descriptors
        self._last_discover = time.monotonic()
        # Warm the capacity stats at startup (least_loaded only) so the FIRST
        # invoke never pays a member's stats round-trip (best-effort, bounded
        # by the per-call stats timeout).
        if self._selection == "least_loaded":
            try:
                await self._refresh_stats(self._transports)
            except Exception:  # noqa: BLE001
                pass
        return self

    async def _discover_all(self) -> list[tuple[Transport, JSON | None | BaseException]]:
        """Parallel discover + identity-pin check over every transport, each
        bounded by ``CHP_ROUTER_DISCOVER_TIMEOUT`` (default 5s — deliberately
        shorter than the transport's invoke timeout: discovery is cheap and
        recurring). Order matches ``self._transports`` (priority order).
        Outcome per transport: descriptor | None (pin mismatch) | exception."""
        probe_timeout = float(os.environ.get("CHP_ROUTER_DISCOVER_TIMEOUT", "5"))

        async def _one(tr: Transport) -> JSON | None:
            descriptor = await asyncio.wait_for(tr.discover(), timeout=probe_timeout)
            if not await asyncio.wait_for(
                    self._check_member_identity(tr), timeout=probe_timeout):
                return None
            return descriptor

        gathered: list[JSON | None | BaseException] = await asyncio.gather(
            *(_one(tr) for tr in self._transports), return_exceptions=True)
        return list(zip(self._transports, gathered))

    async def _check_member_identity(self, tr: Transport) -> bool:
        """Key-pin check ON THE DATA PATH (spec §3.2): at (re)connect, verify the
        member's presented signing key against our ~/.chp/mesh.json pin. A
        mismatch means possible impersonation — the member is refused routing
        until an operator runs `chp-host mesh reset-key`. Members without a URL
        (in-process), without an identity route, at the hash-chain tier (no
        key), or not in the mesh manifest are exempt: pinning only ever
        *tightens* an existing trust relationship, never blocks a new one.
        """
        url = getattr(tr, "url", None)
        identity = getattr(tr, "identity", None)
        if not url or identity is None:
            return True
        try:
            doc = await tr.identity()
        except Exception:  # noqa: BLE001 — no identity route ≠ impersonation
            return True
        key_id = doc.get("key_id") if isinstance(doc, dict) else None
        if not key_id:
            return True
        from .mesh import pin_or_check_key

        status, detail = pin_or_check_key(
            url, key_id, doc.get("public_key"), key_history=doc.get("key_history"))
        if status == "mismatch":
            print(
                f"  WARNING: {tr.name} presented signing key {key_id} but {detail} "
                "is pinned — possible impersonation; refusing routes "
                "(recover deliberately: chp-host mesh reset-key)",
                file=sys.stderr,
            )
            self._mark_unhealthy(tr)
            return False
        return True

    async def _refresh_catalog(self) -> None:
        """Re-discover every host's catalog (parallel, per-probe timeout) so a
        node restart/upgrade (new capabilities or changed input schemas — e.g.
        mlx.chat gaining ``tools``) propagates automatically. Best-effort: a
        host that's momentarily unreachable keeps its last-known catalog (we
        don't drop routes); a total-failure refresh never blanks the table.
        Preserves transport (priority) order."""
        self._last_discover = time.monotonic()  # set first — no refresh stampede
        results = await self._discover_all()
        routes: dict[str, list[Transport]] = {}
        descriptors: dict[str, JSON] = {}
        for tr, outcome in results:
            if isinstance(outcome, BaseException):
                descriptor = self._descriptors.get(tr.name)  # keep last-known
                if not descriptor:
                    continue
            elif outcome is None:  # identity-pin mismatch
                continue
            else:
                descriptor = outcome
                self._mark_healthy(tr)
            descriptors[tr.name] = descriptor
            for cap in descriptor.get("capabilities", []):
                cid = cap.get("id")
                if cid:
                    routes.setdefault(cid, []).append(tr)
        if routes:  # never blank the table on a total-failure refresh
            self._routes = routes
            self._descriptors = descriptors

    async def _maybe_refresh_catalog(self) -> None:
        """TTL-gated inline refresh — OFF the common invoke path since the
        hardening arc (a background refresher keeps the catalog fresh; see
        ``start_catalog_refresher``). Still called inline for an UNKNOWN
        capability so a just-registered capability routes without waiting a
        full refresher tick. The non-blocking lock prevents a stampede of
        concurrent unknown-capability requests all refreshing at once."""
        if _CATALOG_TTL <= 0:
            return
        if time.monotonic() - self._last_discover < _CATALOG_TTL:
            return
        if not self._refresh_lock.acquire(blocking=False):
            return  # another thread is already refreshing — proceed stale
        try:
            await self._refresh_catalog()
        finally:
            self._refresh_lock.release()

    def start_catalog_refresher(self, interval_s: float | None = None):
        """Background catalog refresher (the prober pattern): moves the
        recurring discover fan-out OFF the invoke hot path — before this, the
        first invoke after every catalog-TTL expiry paid a serial
        discover-every-member round-trip (observed as ~30s gateway stalls
        behind one hung member). Fresh event loop per tick, jittered sleep.
        Returns a zero-arg stop callable."""
        import random
        import threading

        interval = float(interval_s if interval_s is not None else _CATALOG_TTL)
        if interval <= 0:
            return lambda: None
        stop = threading.Event()

        def _refresh_loop() -> None:
            while not stop.wait(interval + random.uniform(0, interval * 0.1)):
                try:
                    asyncio.run(self._refresh_catalog())
                except Exception:  # noqa: BLE001 — a bad tick must not kill the loop
                    pass

        threading.Thread(target=_refresh_loop, daemon=True,
                         name=f"chp-catalog-refresh-{self._host_id}").start()
        return stop.set

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
        prefer: str | None = None,
        mandate: JSON | None = None,
        invocation_id: str | None = None,
    ) -> InvocationResult:
        """Route an invocation to a host that owns *capability_id*.

        Tries healthy owners in priority (or round-robin) order, failing over on
        ``ConnectionError``. The same correlation is propagated to whichever host
        runs, so :meth:`replay` can stitch the cross-host timeline.

        *prefer* (optional) expresses node affinity: a transport name or role.
        A matching owner is tried first; if it is down, routing still falls back
        to the other owners (soft pin — availability beats affinity).
        """
        corr = _normalize_correlation(correlation)

        # Gate 0 — gateway exactly-once (spec §13.2, proposal 0014): a client
        # invocation_id this gateway has already served replays from its
        # cross-owner cache — NO owner executes, no failover re-runs. Spans
        # owners AND gateway restarts (the store is persistent). Keyed on the
        # CLIENT's id (forwarded below), so a retry dedupes wherever it would route.
        if invocation_id and self.store is not None:
            from chp_core.host import lookup_recorded_result
            cached = lookup_recorded_result(self.store, invocation_id)
            if cached is not None:
                from chp_core.metrics import record_idempotent_replay
                record_idempotent_replay()
                return cached

        owners = self._routes.get(capability_id)
        if not owners:
            # Unknown capability: one inline TTL-gated refresh (stale-while-
            # revalidate) so a just-registered capability routes without
            # waiting for the background refresher tick. Known capabilities
            # never pay the discover fan-out on the invoke path.
            await self._maybe_refresh_catalog()
            owners = self._routes.get(capability_id)
        if not owners:
            # Unknown mesh-wide is a PROCESSED decision (spec §11), not a raise:
            # HTTP 200, outcome denied, evidence on the gateway's chain.
            return self._deny(
                capability_id, version, corr,
                DenialReason(
                    code="capability_not_found",
                    message=f"no connected host exposes capability {capability_id!r}",
                    retryable=False,
                    details={"hosts": list(self._descriptors.keys())},
                ),
            )

        # Affinity may also ride in metadata (how composition steps and HTTP
        # callers express it). Explicit `prefer` wins; otherwise read metadata.
        if prefer is None and metadata:
            prefer = metadata.get("prefer") or metadata.get("node") or metadata.get("affinity")

        # Capacity-aware routing needs fresh per-node stats; refresh (cached, TTL)
        # before ordering. Never let a stats failure block the actual invocation.
        if self._selection == "least_loaded":
            try:
                await self._refresh_stats(owners)
            except Exception:
                pass

        candidates = self._ordered_candidates(capability_id, owners, prefer=prefer)

        last_error: Exception | None = None
        attempted: list[str] = []
        # ONE envelope — and therefore ONE invocation_id — across every owner
        # attempt (spec §13): an owner that already executed before the
        # connection dropped replays its recorded result instead of the
        # failover double-executing on the next owner.
        envelope = InvocationEnvelope(
            capability_id=capability_id,
            payload=payload or {},
            version=version,
            mode=mode,
            correlation=corr,
            subject=subject or {"id": "router", "type": "system"},
            metadata=dict(metadata or {}),
            # The CLIENT's invocation_id transits UNCHANGED (§13.2): one id
            # client → gateway → owner, so the gateway cache above and the owner's
            # own §13 gate 0 key on the same id. Absent → the envelope mints ONE
            # (reused across failover; per-call, un-cacheable — matching per-host §13).
            **({"invocation_id": invocation_id} if invocation_id else {}),
            # Forwarding rule (§10, proposal 0004): a presented mandate
            # transits UNCHANGED — the executing host's gate 5 verifies it
            # and rebinds the subject; authority survives the hop even
            # though the transport subject (router) does not.
            mandate=mandate,
        )
        for tr in candidates:
            envelope.metadata = {**(metadata or {}), "routed_via": tr.name}
            try:
                result = await tr.ainvoke_envelope(envelope)
            except ConnectionError as exc:
                last_error = exc
                attempted.append(tr.name)
                # A mid-invoke transition rides THIS correlation (§11) so the
                # failover is replayable in-context.
                self._mark_unhealthy(tr, correlation=corr)
                from chp_core.metrics import record_routing_failover
                record_routing_failover()
                continue
            self._mark_healthy(tr, correlation=corr)
            # Gateway exactly-once (§13.2): cache the owner's DEFINITIVE result
            # under the client id so any future retry replays without re-routing.
            # Only owner-returned outcomes are cached here — the gateway's own
            # routing denials (capability_not_found / retryable host_unreachable
            # below) are NOT, so a transient unreachable stays retryable.
            if invocation_id and self.store is not None and not result.replayed:
                try:
                    self.store.record_result(invocation_id, result.to_dict())
                except Exception:  # noqa: BLE001 — recording must never fail an invoke
                    pass
            return result

        # No owner reachable: the mesh could not place the work — a PROCESSED
        # denial with the reserved transport code (spec §11), never a bare 5xx.
        from chp_core.metrics import record_unreachable_denial
        record_unreachable_denial()
        return self._deny(
            capability_id, version, corr,
            DenialReason(
                code="host_unreachable",
                message=f"no reachable host for capability {capability_id!r}",
                retryable=True,
                details={
                    "attempted_hosts": attempted,
                    "last_error": str(last_error) if last_error else None,
                    "retry_after_s": int(self._recheck_interval),
                },
            ),
        )

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
            "id": self._host_id,
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
        stitched view stays attributable. Ordering is **chp-causal-order-v1**
        (chp-v0.2.md): causally consistent (per-host sequence + causation
        edges), deterministic tiebreak for concurrent events — not the previous
        wall-clock-only sort, which could order a child before its cross-host
        cause under clock skew.
        """
        events, _missing = await self._replay_with_missing(correlation_id)
        return events

    async def _replay_with_missing(self, correlation_id: str) -> tuple[list[JSON], list[str]]:
        """Replay fan-out that also reports which members could not contribute —
        a merged timeline is never silently partial (chp-http-binding.md §4)."""
        from chp_core.ordering import order_events

        events: list[JSON] = []
        missing: list[str] = []
        for tr in self._transports:
            if not self._is_healthy(tr):
                missing.append(tr.name)
                continue
            try:
                result = await tr.replay_result(correlation_id)
            except ConnectionError:
                self._mark_unhealthy(tr)
                missing.append(tr.name)
                continue
            for event in result.get("events", []):
                events.append({**event, "_host": tr.name})
        # The gateway's own chain (routing denials, health transitions — §11)
        # is part of the stitched story, not an operational side channel.
        if self.store is not None:
            try:
                for event in self.store.by_correlation(correlation_id):
                    events.append({**event, "_host": self._host_id})
            except Exception:  # noqa: BLE001 — members' evidence still merges
                pass
        return order_events(events), missing

    async def export_task_bundle(self, correlation_id: str) -> JSON:
        """Assemble the cross-host task bundle (chp-v0.2.md §8) at request time.

        Fans out ``export_bundle`` to every member, keeps members with ≥1 event,
        and aggregates. An UNREACHABLE member raises — a silently-partial
        evidence bundle is the failure mode task bundles exist to prevent; the
        caller retries. Evidence is never centralized: members export their own
        signed bundles; the gateway only assembles."""
        from chp_core.signing import build_task_bundle
        from chp_core.types import utc_now

        members: list[JSON] = []
        unreachable: list[str] = []
        for tr in self._transports:
            exporter = getattr(tr, "export_bundle", None)
            if exporter is None:
                continue
            try:
                bundle = await exporter(correlation_id)
            except Exception:
                unreachable.append(tr.name)
                continue
            if bundle.get("events"):
                members.append(bundle)
        if unreachable:
            raise ConnectionError(
                f"task bundle incomplete — unreachable hosts: {', '.join(unreachable)}")
        if not members:
            raise LookupError(f"no evidence for correlation {correlation_id!r} on any host")
        task = build_task_bundle(correlation_id, members, created_at=utc_now())
        # Aggregator signature (chp-v0.2.md §8): when this gateway holds a key,
        # sign the assembly so "who assembled the set" is provable, not asserted.
        from chp_core.signing import (
            load_configured_anchors, load_host_key, resolve_key_dir, sign_task_bundle)
        key_dir = resolve_key_dir(self._host_id)
        key = load_host_key(key_dir)
        if key is not None and key.can_sign:
            task = sign_task_bundle(
                task, key, aggregator_host_id=self._host_id,
                anchors=load_configured_anchors(key_dir) or None)
        return task

    async def ainvoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        """Route a pre-built envelope through the routing table.

        Delegates to :meth:`ainvoke` so priority, failover, and round-robin
        selection all apply. Enables ``serve_http(router)`` by satisfying the
        same duck-type surface as ``LocalCapabilityHost``.
        """
        if isinstance(envelope, dict):
            envelope = InvocationEnvelope.from_mapping(envelope)
        # Affinity travels in metadata ({"prefer": "<name|role>"}) so callers can
        # pin a node over plain HTTP without a wire-protocol change; ainvoke()
        # reads it from metadata.
        return await self.ainvoke(
            envelope.capability_id,
            envelope.payload,
            version=envelope.version,
            correlation=envelope.correlation,
            subject=envelope.subject,
            mode=envelope.mode,
            metadata=envelope.metadata,
            mandate=envelope.mandate,
            # Gateway exactly-once (§13.2): the client's id (from_mapping guarantees
            # one at ingress) drives the cross-owner gate 0.
            invocation_id=envelope.invocation_id,
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
        events, missing = asyncio.run(self._replay_with_missing(correlation_id))
        return ReplayResult(
            correlation_id=correlation_id,
            events=events,
            event_count=len(events),
            partial=bool(missing),
            missing_hosts=missing,
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

    def start_prober(self, interval_s: float):
        """Background health prober (non-normative reference feature — spec §11
        deliberately defines none): a daemon thread runs :meth:`health` every
        *interval_s* seconds so unreachability is detected — and the §11
        transition evidence emitted — CONTINUOUSLY, not only when an invocation
        happens to fail. ``health()`` already probes every transport and calls
        the transition-gated markers, so the prober is pure scheduling. Runs a
        fresh event loop per tick (the same pattern the HTTP handler threads
        use), off any running loop. Returns a zero-arg stop callable."""
        import threading

        stop = threading.Event()

        def _probe_loop() -> None:
            while not stop.wait(interval_s):
                try:
                    asyncio.run(self.health())
                except Exception:  # noqa: BLE001 — a bad tick must not kill the prober
                    pass

        threading.Thread(target=_probe_loop, daemon=True,
                         name=f"chp-prober-{self._host_id}").start()
        return stop.set

    # ── health bookkeeping ──────────────────────────────────────────────────────

    def _matches_prefer(self, tr: Transport, prefer: str) -> bool:
        """A transport matches an affinity hint by its name or its role."""
        return tr.name == prefer or self._host_roles.get(tr.name) == prefer

    async def _refresh_stats(self, owners: list[Transport]) -> None:
        """Refresh cached host.stats for *owners* whose snapshot is stale (TTL).

        Best-effort: a node without the host adapter (or unreachable) is simply
        left without stats and sorts last in capacity routing.
        """
        now = time.monotonic()
        for tr in owners:
            if not self._is_healthy(tr):
                continue
            cached = self._stats_cache.get(tr.name)
            if cached and (now - cached[0]) < _STATS_TTL:
                continue
            envelope = InvocationEnvelope(
                capability_id="chp.adapters.host.stats",
                payload={},
                subject={"id": "router", "type": "system"},
                metadata={"routed_via": tr.name},
            )
            # Short stats budget (default 2s): this refresh runs ON the
            # invoke path in least_loaded mode — a cold/slow member must not
            # hold the caller for the full transport timeout (the ~30s
            # cold-start stall of the 0.15.0 live proof).
            stats_timeout = float(os.environ.get("CHP_ROUTER_STATS_TIMEOUT", "2"))
            try:
                result = await asyncio.wait_for(
                    tr.ainvoke_envelope(envelope), timeout=stats_timeout)
            except Exception:
                continue
            data = getattr(result, "data", None)
            if isinstance(data, dict):
                self._stats_cache[tr.name] = (now, data)

    def _capacity_score(self, capability_id: str, name: str) -> float:
        """Lower is better. GPU utilization for inference capabilities, else
        normalized CPU load. Missing stats sort last (inf)."""
        cached = self._stats_cache.get(name)
        if not cached:
            return float("inf")
        stats = cached[1]
        if any(h in capability_id for h in _INFERENCE_HINTS):
            gpu = stats.get("gpu")
            if isinstance(gpu, dict) and isinstance(gpu.get("utilization_pct"), (int, float)):
                return float(gpu["utilization_pct"])
        lpc = stats.get("load_per_core")
        return float(lpc) if isinstance(lpc, (int, float)) else float("inf")

    def _ordered_candidates(
        self, capability_id: str, owners: list[Transport], prefer: str | None = None
    ) -> list[Transport]:
        # Routing-strategy seam: this is where capability invocations are ordered
        # across the nodes that own them. "first" (priority/insertion order) and
        # "round_robin" (load spread) set the base order; *prefer* (node affinity
        # by name or role) then floats a matching owner to the front. Future
        # capacity/locality-aware strategies plug in here by reordering `healthy`
        # on additional signals (node load, region). Base strategy comes from the
        # gateway's `selection` config (mesh.json → gateway.selection).
        healthy = [tr for tr in owners if self._is_healthy(tr)]
        unhealthy = [tr for tr in owners if not self._is_healthy(tr)]
        if self._selection == "round_robin" and len(healthy) > 1:
            idx = self._rr.get(capability_id, 0) % len(healthy)
            self._rr[capability_id] = idx + 1
            healthy = healthy[idx:] + healthy[:idx]
        elif self._selection == "least_loaded" and len(healthy) > 1:
            # Route to the node with the most headroom. GPU utilization for
            # inference capabilities, normalized CPU load otherwise; nodes with no
            # stats sort last. Stable sort keeps insertion order among ties.
            healthy.sort(key=lambda tr: self._capacity_score(capability_id, tr.name))
        if prefer:
            # Soft affinity: preferred owners first, the rest keep their order.
            preferred = [tr for tr in healthy if self._matches_prefer(tr, prefer)]
            others = [tr for tr in healthy if not self._matches_prefer(tr, prefer)]
            healthy = preferred + others
        # Healthy owners first; unhealthy kept as a last resort (they may have recovered).
        return healthy + unhealthy

    def _is_healthy(self, tr: Transport) -> bool:
        until = self._unhealthy.get(tr.name)
        if until is None:
            return True
        if time.monotonic() < until:
            return False
        # Recheck window elapsed — HALF-OPEN: admit exactly ONE trial at a
        # time (the probe flag clears on success via _mark_healthy or on
        # failure via _mark_unhealthy). The entry itself stays until an actual
        # SUCCESS clears it: the unhealthy→healthy transition must be
        # observable (§11 emission is transition-gated, which needs the prior
        # state to still be here when the host proves back).
        if self._half_open_probe.get(tr.name):
            return False
        self._half_open_probe[tr.name] = True
        return True

    def _mark_unhealthy(self, tr: Transport, *,
                        correlation: CorrelationContext | None = None) -> None:
        self._half_open_probe.pop(tr.name, None)
        # Failure-counting breaker: only the Nth CONSECUTIVE failure trips the
        # unhealthy state (threshold 1 = trip immediately, the pre-0.16
        # behavior). In-invoke failover is unaffected — the caller already
        # skipped to the next owner; this gates only the routing-order state.
        self._failure_counts[tr.name] = self._failure_counts.get(tr.name, 0) + 1
        already_unhealthy = tr.name in self._unhealthy
        if not already_unhealthy and self._failure_counts[tr.name] < self._breaker_threshold:
            return
        # Window escalation: repeated trips back off exponentially, capped.
        trips = self._trip_counts.get(tr.name, 0) + (0 if already_unhealthy else 1)
        self._trip_counts[tr.name] = trips
        window = min(self._recheck_interval * (2 ** max(0, trips - 1)),
                     self._recheck_interval * 8)
        is_transition = not already_unhealthy
        self._unhealthy[tr.name] = time.monotonic() + window
        if is_transition:
            self._emit_routing_event(
                "host_marked_unhealthy",
                {"host": tr.name, "recheck_after_s": int(window)},
                correlation=correlation,
            )

    def _mark_healthy(self, tr: Transport, *,
                      correlation: CorrelationContext | None = None) -> None:
        self._half_open_probe.pop(tr.name, None)
        self._failure_counts.pop(tr.name, None)
        self._trip_counts.pop(tr.name, None)
        if self._unhealthy.pop(tr.name, None) is not None:
            self._emit_routing_event(
                "host_marked_healthy", {"host": tr.name}, correlation=correlation)

    # ── gateway evidence (spec §11) ─────────────────────────────────────────────

    def _emit_routing_event(
        self,
        event_type: str,
        payload: JSON,
        *,
        correlation: CorrelationContext | None = None,
        invocation_id: str | None = None,
        capability_id: str = "chp.routing",
        version: str | None = None,
        outcome: str | None = None,
        denial: DenialReason | None = None,
    ) -> ExecutionEvidence | None:
        """Append one event to the gateway's own chain. No store = no-op (the
        returned-denial floor). Health transitions without an invocation ride a
        stable per-gateway correlation so `chp replay routing-<host_id>` tells
        the fabric's whole story."""
        if self.store is None:
            return None
        event = ExecutionEvidence(
            event_id=new_id("evt"),
            event_type=event_type,
            invocation_id=invocation_id or new_id("inv"),
            capability_id=capability_id,
            capability_version=version,
            host_id=self._host_id,
            correlation=correlation
            or CorrelationContext(correlation_id=f"routing-{self._host_id}"),
            timestamp=utc_now(),
            outcome=outcome,  # type: ignore[arg-type]
            payload=payload,
            redacted=False,
            denial=denial,
        )
        try:
            return self.store.append(event)
        except Exception as exc:  # noqa: BLE001 — a broken store must not break routing
            print(f"  WARNING: gateway evidence append failed: {exc}", file=sys.stderr)
            return None

    def _deny(
        self,
        capability_id: str,
        version: str | None,
        correlation: CorrelationContext,
        denial: DenialReason,
    ) -> InvocationResult:
        """A PROCESSED routing denial — mirrors host.py:_deny's event shape so
        gateway denials look exactly like host denials in evidence and metrics
        (`execution_denied` is already a metrics event)."""
        invocation_id = new_id("inv")
        denied = self._emit_routing_event(
            "execution_denied",
            {"reason": denial.code},
            correlation=correlation,
            invocation_id=invocation_id,
            capability_id=capability_id,
            version=version,
            outcome="denied",
            denial=denial,
        )
        return InvocationResult(
            invocation_id=invocation_id,
            capability_id=capability_id,
            capability_version=version,
            correlation=correlation,
            outcome="denied",
            success=False,
            denial=denial,
            evidence_ids=[denied.event_id] if denied else [],
            started_at=denied.timestamp if denied else None,
        )
