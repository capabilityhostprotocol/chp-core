"""The host (queryable) side of the Zenoh binding — ``ZenohHostServer``."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import os
import threading
from typing import Any

from chp_core.types import InvocationEnvelope, JSON

from .keys import KEY_PREFIX, keys
from .presence import Presence
from .pubsub import Stream
from .session import open_session


class ZenohHostServer:
    """Serve a ``LocalCapabilityHost`` over Zenoh — the queryable side of the binding.

    Declares queryables for invoke / discover / replay / export / health and publishes each handled
    invocation's completed evidence to the evidence stream. Optionally declares a liveliness presence
    token (push-based up/down) and can publish to the async HITL decision stream.
    """

    def __init__(self, host: Any, *, session: Any = None, config: Any = None,
                 host_id: str | None = None, prefix: str = KEY_PREFIX,
                 declare_presence: bool = False, max_invoke_workers: int | None = None) -> None:
        self._host = host
        self.host_id = host_id or getattr(host, "host_id", "local-chp-host")
        self._k = keys(self.host_id, prefix=prefix)
        self._session, self._owns = open_session(session, config)
        self._evidence = Stream(self._session, self._k["evidence"])
        self._decisions = Stream(self._session, self._k["decisions"])
        self._presence_token: Any = None
        # An invocation must NOT run on a Zenoh callback thread: one long invocation (e.g. a ~20-min
        # sovereign-model generation) would block it and starve health/discover/other queries, silently
        # dropping the whole node off the mesh. Zenoh's built-in answer is a CHANNEL handler — the runtime
        # enqueues each invoke query (never blocked) and we drain + reply from our own thread(s); the
        # channel also keeps each Query alive until we reply. The cheap/fast queryables
        # (discover/health/replay/export) stay as callbacks — they never block.
        import zenoh  # importable now: open_session succeeded above
        qcap = int(os.environ.get("CHP_ZENOH_INVOKE_QUEUE", "64") or "64")
        # Default 1 worker keeps invocations serial (same semantics as the old inline path — no new
        # host/store concurrency); raise CHP_ZENOH_INVOKE_WORKERS only when both are concurrency-safe.
        workers = max_invoke_workers if max_invoke_workers is not None \
            else int(os.environ.get("CHP_ZENOH_INVOKE_WORKERS", "1") or "1")
        self._invoke_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, workers), thread_name_prefix="chp-zenoh-invoke")
        self._invoke_q = self._session.declare_queryable(
            self._k["invoke"], handler=zenoh.handlers.FifoChannel(qcap))
        self._queryables = [
            self._invoke_q,
            self._session.declare_queryable(self._k["declarations"], self._on_discover),
            self._session.declare_queryable(self._k["replay"], self._on_replay),
            self._session.declare_queryable(self._k["export"], self._on_export),
            self._session.declare_queryable(self._k["health"], self._on_health),
        ]
        self._draining = True
        self._drainer = threading.Thread(
            target=self._drain_invokes, name="chp-zenoh-invoke-drain", daemon=True)
        self._drainer.start()
        if declare_presence:
            self.declare_presence()

    # ── presence + decision streams (pub/sub extensions) ───────────────────────

    def declare_presence(self) -> Any:
        """Declare this host ALIVE via a Zenoh liveliness token at its presence key. Watchers see it go
        down the instant this process dies/disconnects — no heartbeat needed. Idempotent."""
        if self._presence_token is None:
            self._presence_token = Presence(self._session).declare(self._k["presence"])
        return self._presence_token

    def publish_decision(self, decision: JSON) -> None:
        """Publish an async HITL decision (``{approval_id, decision, by}``) to this host's decision
        stream — control subscribes and resolves the approval queue without a blocking query."""
        self._decisions.publish(decision)

    # ── queryable handlers (each replies with a wire JSON object) ──────────────

    def _reply(self, query: Any, key: str, obj: JSON) -> None:
        query.reply(key, json.dumps(obj).encode())

    def _drain_invokes(self) -> None:
        """Pull invoke queries off the FifoChannel and run each on the worker pool — off the Zenoh
        callback thread, so a long invocation never starves health/discover/other queries. recv() blocks
        for the next query and raises once the queryable is undeclared (close), ending the loop."""
        while self._draining:
            try:
                query = self._invoke_q.recv()
            except Exception:  # noqa: BLE001 — queryable undeclared / session closed → stop draining
                break
            if query is None:
                break
            self._invoke_pool.submit(self._handle_invoke, query)

    def _handle_invoke(self, query: Any) -> None:
        """Run one invocation off the callback thread and reply. Never raise: a worker that dies without
        replying would leave the querier hanging to timeout, so any failure still sends a reply."""
        try:
            env = InvocationEnvelope.from_mapping(json.loads(bytes(query.payload)))
            result = asyncio.run(self._host.ainvoke_envelope(env))
            self._reply(query, self._k["invoke"], result.to_dict())
            # Native evidence pub/sub (§4): broadcast this invocation's completed
            # evidence — something the HTTP binding's request/response cannot do.
            for ev in self._host.replay(env.correlation.correlation_id):
                if ev.get("event_type") == "execution_completed":
                    self._evidence.publish(ev)
        except Exception as exc:  # noqa: BLE001 — a worker must always reply, never crash the pool
            with contextlib.suppress(Exception):
                self._reply(query, self._k["invoke"],
                            {"success": False, "outcome": "error", "error": f"invoke_failed: {exc}"})
        finally:
            # A channel handler owns the Query lifetime: drop() finalizes it so the querier's get()
            # returns immediately. (The callback path did this implicitly on return; without it the
            # querier waits the full timeout even though the reply was already sent.)
            with contextlib.suppress(Exception):
                query.drop()

    def _on_discover(self, query: Any) -> None:
        desc = self._host.discover()
        self._reply(query, self._k["declarations"],
                    asyncio.run(desc) if asyncio.iscoroutine(desc) else desc)

    def _on_replay(self, query: Any) -> None:
        q = json.loads(bytes(query.payload)) if query.payload else {}
        corr = q.get("correlation_id", "")
        self._reply(query, self._k["replay"], {"events": self._host.replay(corr)})

    def _on_export(self, query: Any) -> None:
        # SIGNED evidence bundle for a correlation — the denial evidence an approval ingests +
        # offline-verifies. Byte-identical to the HTTP export: same build_bundle + sign_bundle over
        # the same store, so verify_bundle (hash chain + root + host sig + pinned key) is unchanged.
        from chp_core import signing
        from chp_core.types import utc_now
        q = json.loads(bytes(query.payload)) if query.payload else {}
        corr = q.get("correlation_id", "")
        events = self._host.store.export_correlation(corr)
        bundle = signing.build_bundle(self._host.host_id, events, created_at=utc_now())
        key_dir = signing.resolve_key_dir(self._host.host_id)
        key = signing.load_host_key(key_dir)
        if key is not None and key.can_sign:
            bundle = signing.sign_bundle(
                bundle, key, anchors=signing.load_configured_anchors(key_dir) or None)
        self._reply(query, self._k["export"], bundle)

    def _on_health(self, query: Any) -> None:
        desc = self._host.discover()
        desc = asyncio.run(desc) if asyncio.iscoroutine(desc) else desc
        self._reply(query, self._k["health"], {
            "status": "ok", "host_id": self.host_id, "protocol": "chp",
            "capability_count": len(desc.get("capabilities", [])),
        })

    def close(self) -> None:
        self._draining = False   # stop the drainer; undeclaring the invoke queryable unblocks its recv()
        if self._presence_token is not None:
            try:
                self._presence_token.undeclare()
            except Exception:  # noqa: BLE001
                pass
        for q in self._queryables:
            try:
                q.undeclare()
            except Exception:  # noqa: BLE001
                pass
        self._invoke_pool.shutdown(wait=False, cancel_futures=True)
        if self._owns:
            self._session.close()
