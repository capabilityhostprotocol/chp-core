"""Small HTTP surface for serving a local CHP host and a client for remote hosts."""

from __future__ import annotations

import asyncio
import hmac
import inspect
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

from .host import LocalCapabilityHost
from .metrics import aggregate_session_metrics, aggregate_token_metrics, format_prometheus, format_token_prometheus
from .types import (
    CorrelationContext,
    DenialReason,
    InvocationEnvelope,
    InvocationResult,
    JSON,
    ReplayQuery,
)

logger = logging.getLogger(__name__)


def _host_version() -> str:
    """Return the installed chp-host package version (the unit `chp-host update`
    upgrades), without importing chp_host — chp_core must not depend on it.
    Falls back to chp-core, then "unknown"."""
    from importlib.metadata import PackageNotFoundError, version
    for pkg in ("chp-host", "chp-core"):
        try:
            return version(pkg)
        except PackageNotFoundError:
            continue
    return "unknown"


def _scope_allows(scope: list[str], capability_id: str) -> bool:
    """Exact id or trailing-* prefix match, e.g. `chp.adapters.audit.*`."""
    return any(
        capability_id == s or (s.endswith("*") and capability_id.startswith(s[:-1]))
        for s in scope
    )


def _host_assurance(host_id: str | None = None) -> JSON:
    """Declared evidence assurance tier for this host (v0.2). `signed` when a
    host keypair is present, else `hash-chain` (the store always chains).
    Verifiers reject a lower-than-expected tier rather than degrade silently.

    A signed host also serves its self-signed `host_identity` attestation so a
    mesh peer can verify the key self-attests this host_id *before* pinning it
    (chp-v0.2.md §3) — not blindly trust whatever /host reports."""
    try:
        from .signing import load_host_key, resolve_key_dir
        key_dir = resolve_key_dir(host_id)
        key = load_host_key(key_dir)
    except Exception:
        key = None
    if key is None:
        return {"assurance": "hash-chain"}
    out: JSON = {"assurance": "signed", "key_id": key.key_id, "public_key": key.public_key_b64}
    if host_id and key.can_sign:
        try:
            from .signing import load_configured_anchors, load_or_build_attestation
            # Anchors (spec §3.1): configured anchors (e.g. a did anchor from
            # `chp anchor-did`) + a CHP_HOST_DOMAIN domain anchor. These become
            # the trust roots a never-met verifier can check. None → TOFU floor.
            anchors = list(load_configured_anchors(key_dir))
            domain = os.environ.get("CHP_HOST_DOMAIN")
            if domain and not any(a.get("type") == "domain" for a in anchors):
                anchors.append({"type": "domain", "domain": domain})
            # Persisted, not rebuilt per request — stable valid_from + anchors.
            out["host_identity"] = load_or_build_attestation(host_id, key, anchors or None, key_dir)
            # Key lifecycle (spec §3.2): rotation lineage + revocations, so a
            # resolving verifier can follow continuity and see revoked keys.
            from .signing import load_key_history, load_revocations
            history = load_key_history(key_dir)
            if history:
                out["key_history"] = history
            revocations = load_revocations(key_dir)
            if revocations:
                out["revoked_keys"] = revocations
        except Exception:
            pass
    return out


class CapabilityHostHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server bound to a CHP host (LocalCapabilityHost or MultiHostRouter)."""

    def __init__(self, server_address: tuple[str, int], host: Any) -> None:
        super().__init__(server_address, CapabilityHostRequestHandler)
        self.chp_host = host


class CapabilityHostRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON API for CHP v0.1 discovery, invocation, and replay."""

    server: CapabilityHostHTTPServer

    # Slowloris guard: drop connections that stall mid-request rather than
    # pinning a server thread indefinitely. BaseHTTPRequestHandler applies this
    # as the per-request socket timeout.
    timeout = 30

    # Cap request bodies read into memory (DoS guard). Override via env.
    _MAX_BODY_BYTES = int(os.environ.get("CHP_HOST_MAX_BODY_BYTES", str(8 * 1024 * 1024)))

    def _check_auth(self) -> bool:
        """Return True if the request is authorized (or auth is not configured).

        Also records the *authenticated caller* on ``self._caller`` (a verified
        principal name, or None for the anonymous shared-key / no-auth case) so
        the invoke path can bind a VERIFIED subject to the evidence — the
        difference between "claims to be agent X" and "is agent X".

        Per-caller keys: ``CHP_HOST_API_KEYS="agent-a:key1,steward:key2"`` — a
        match sets the caller to that name. ``CHP_HOST_API_KEY`` stays as the
        anonymous shared-key fallback.

        Rotation overlap (binding §2): the same name MAY appear with several
        keys ("a:new,a:old") — every entry is checked, so rotation is add-new,
        drain, remove-old with no auth gap.

        Capability scope (binding §2): a third field scopes the key —
        ``name:key:chp.adapters.audit.*|conformance.echo``. An out-of-scope
        invocation is a PROCESSED denial (``policy_blocked``, HTTP 200, with
        evidence) — governance, not transport rejection.
        """
        self._caller: str | None = None
        self._caller_scope: list[str] | None = None
        presented = self.headers.get("X-CHP-Key", "")
        named = os.environ.get("CHP_HOST_API_KEYS")
        shared = os.environ.get("CHP_HOST_API_KEY")

        if named:
            for entry in named.split(","):
                parts = entry.split(":", 2)
                if len(parts) < 2:
                    continue
                if hmac.compare_digest(presented, parts[1].strip()):
                    self._caller = parts[0].strip()
                    if len(parts) == 3 and parts[2].strip():
                        self._caller_scope = [s.strip() for s in parts[2].split("|") if s.strip()]
                    return True
        if shared and hmac.compare_digest(presented, shared):
            return True  # anonymous authenticated (single shared key)
        if not named and not shared:
            return True  # no auth configured — open

        self._write_error(HTTPStatus.UNAUTHORIZED, "unauthorized", "Missing or invalid X-CHP-Key")
        return False

    def _sync_discover(self) -> JSON:
        """Call discover() on either a LocalCapabilityHost (sync) or MultiHostRouter (async)."""
        host = self.server.chp_host
        if inspect.iscoroutinefunction(host.discover):
            return asyncio.run(host.discover())
        return host.discover()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        # /health is always public — required for mesh probes and load balancers
        if path == "/" or path == "/health":
            host_desc = self._sync_discover()
            # /health is unauthenticated — do not disclose live capability_count
            # here (mesh-count privacy). It stays on the authed /host descriptor.
            self._write_json({
                "status": "ok",
                "host_id": host_desc.get("id") or host_desc.get("hosts", ["unknown"])[0],
                "protocol": "chp",
                # Same rule as /host: v0.2 surface (hash-chain/signed) → "0.2".
                "version": "0.2" if _host_assurance().get("assurance") in ("hash-chain", "signed") else "0.1",
                "host_version": _host_version(),
            })
            return
        if path == "/.well-known/chp-identity":
            # PUBLIC (like /health): a never-met verifier must be able to resolve
            # this host's key without credentials — the doc's authority comes from
            # the TLS origin serving it, not from auth (spec §3 Anchors). Serves
            # only key/identity material; capability data stays behind auth.
            desc = self._sync_discover()
            host_id = desc.get("id") or (desc.get("hosts") or [None])[0]
            self._write_json(_host_assurance(host_id))
            return
        if not self._check_auth():
            return
        if path == "/host":
            desc = self._sync_discover()
            desc.setdefault("host_version", _host_version())
            host_id = desc.get("id") or (desc.get("hosts") or [None])[0]
            for k, v in _host_assurance(host_id).items():
                desc.setdefault(k, v)
            # v0.2 is an additive superset (spec/README.md): a host serving the
            # v0.2 surface (hash-chain/signed tier) advertises 0.2.
            if desc.get("assurance") in ("hash-chain", "signed"):
                desc["protocol_version"] = "0.2"
            self._write_json(desc)
            return
        if path == "/capabilities":
            self._write_json({"capabilities": self._sync_discover()["capabilities"]})
            return
        if path.startswith("/replay/"):
            correlation_id = unquote(path.removeprefix("/replay/"))
            result = self.server.chp_host.replay_result(correlation_id)
            self._write_json(result.to_dict() if hasattr(result, "to_dict") else result)
            return
        if path.startswith("/verify/"):
            correlation_id = unquote(path.removeprefix("/verify/"))
            # Gateway-ness is detected by the FEDERATED capability, never by the
            # absence of a store: a router MAY hold its own store (§11 routing
            # evidence) and /verify must still be federated — the evidence for a
            # routed correlation lives on the members, not the gateway.
            if hasattr(self.server.chp_host, "export_task_bundle") or not hasattr(
                    self.server.chp_host, "store"):
                # Gateway: FEDERATED verification (chp-v0.2.md §8) — assemble the
                # task bundle from member exports and verify it as a unit. Falls
                # back to the honest note when members can't export.
                if hasattr(self.server.chp_host, "export_task_bundle"):
                    try:
                        task = asyncio.run(
                            self.server.chp_host.export_task_bundle(correlation_id))
                        from .signing import verify_task_bundle
                        tv = verify_task_bundle(task)
                        from .metrics import record_verification
                        record_verification(tv.valid)
                        self._write_json({
                            "mode": "federated", "valid": tv.valid,
                            "assurance": tv.assurance, "checks": tv.checks,
                            "hosts": tv.hosts, "correlation_id": correlation_id,
                            "task_root_hash": tv.task_root_hash, "reason": tv.reason,
                        })
                        return
                    except Exception as exc:
                        self._write_error(HTTPStatus.SERVICE_UNAVAILABLE,
                                          "federated_verify_unavailable", str(exc))
                        return
                self._write_json({
                    "note": "Verification not available in gateway mode — evidence is distributed.",
                    "correlation_id": correlation_id,
                    "hosts": list(getattr(self.server.chp_host, "_descriptors", {}).keys()),
                })
                return
            result = self.server.chp_host.store.verify_chain(correlation_id)
            from .metrics import record_verification
            record_verification(result.valid, chain_break=not result.valid)
            self._write_json(asdict(result))
            return
        if path.startswith("/export/"):
            correlation_id = unquote(path.removeprefix("/export/"))
            # Gateway: the assembled cross-host task bundle (503 on partial).
            if hasattr(self.server.chp_host, "export_task_bundle"):
                try:
                    task = asyncio.run(self.server.chp_host.export_task_bundle(correlation_id))
                except Exception as exc:
                    self._write_error(HTTPStatus.SERVICE_UNAVAILABLE,
                                      "export_incomplete", str(exc))
                    return
                self._write_json(task)
                return
            # Single host: this host's (signed when keyed) bundle.
            if not hasattr(self.server.chp_host, "store"):
                self._write_error(HTTPStatus.NOT_FOUND, "not_found", "no evidence store")
                return
            from . import signing
            from .types import utc_now
            events = self.server.chp_host.store.export_correlation(correlation_id)
            host_id = getattr(self.server.chp_host, "host_id", "unknown")
            bundle = signing.build_bundle(host_id, events, created_at=utc_now())
            key_dir = signing.resolve_key_dir(host_id)
            key = signing.load_host_key(key_dir)
            if key is not None and key.can_sign:
                from .signing import load_configured_anchors
                bundle = signing.sign_bundle(bundle, key,
                                             anchors=load_configured_anchors(key_dir) or None)
            self._write_json(bundle)
            return
        if path == "/metrics":
            self._write_metrics()
            return
        if path == "/head":
            # Witnessing (spec §12): the store head a peer countersigns. AUTHED
            # (the sequence discloses activity volume — mesh-count privacy).
            # Leaves stay LOCAL: the witness signs only the root.
            store = getattr(self.server.chp_host, "store", None)
            if store is None or not hasattr(store, "get_store_head"):
                self._write_error(HTTPStatus.NOT_FOUND, "not_found", "no evidence store")
                return
            head = store.get_store_head()
            from .types import utc_now
            self._write_json({
                "host_id": getattr(self.server.chp_host, "host_id",
                                   getattr(self.server.chp_host, "_host_id", "unknown")),
                "scheme": head["scheme"],
                "sequence": head["sequence"],
                "store_head": head["store_head"],
                "at": utc_now(),
            })
            return
        if path == "/witnesses":
            # Received countersignatures over THIS host's head — the audit
            # story a host serves about itself. Statements only; the leaves
            # snapshots stay local (they name correlations).
            from . import witnessing
            self._write_json({
                "witnesses": [r.get("statement") for r in witnessing.load_received()],
            })
            return
        self._write_error(HTTPStatus.NOT_FOUND, "not_found", f"Unknown route: {path}")

    def _write_metrics(self) -> None:
        """Serve Prometheus text metrics aggregated over the last hour of evidence."""
        host = self.server.chp_host
        store = getattr(host, "store", None)
        if store is None:
            body = b"# /metrics not available in gateway mode\n"
            self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        since = (datetime.now(tz=timezone.utc) - timedelta(hours=1)).isoformat()
        events = store.query(since=since)
        report = aggregate_session_metrics("live", events)
        token_report = aggregate_token_metrics(events)
        from .metrics import format_integrity_prometheus
        body = (
            format_prometheus(report).encode("utf-8")
            + b"\n"
            + format_token_prometheus(token_report).encode("utf-8")
            + b"\n"
            + format_integrity_prometheus().encode("utf-8")
        )
        # Routing reliability (spec §11) — only a router has an _unhealthy map.
        unhealthy = getattr(host, "_unhealthy", None)
        if unhealthy is not None:
            from .metrics import format_routing_prometheus
            body += b"\n" + format_routing_prometheus(len(unhealthy)).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._check_auth():
            return
        path = urlparse(self.path).path
        try:
            body = self._read_json()
            if path == "/invoke":
                if body.get("mode") == "stream":
                    self._invoke_stream(body)
                else:
                    self._write_json(self._invoke(body))
                return
            if path == "/v1/chat/completions":
                # OpenAI-compatible shim → routes chat through chp.adapters.mlx.chat
                # (capacity-routed + evidenced). Lets any OpenAI client use mesh
                # inference as a governed capability; tool-calling flows through too.
                if body.get("stream"):
                    self._openai_chat_stream(body)
                else:
                    self._write_json(self._openai_chat(body))
                return
            if path == "/replay":
                query = ReplayQuery.from_mapping(body)
                result = self.server.chp_host.replay_result(query)
                self._write_json(result.to_dict() if hasattr(result, "to_dict") else result)
                return
            if path == "/witness":
                self._receive_witness(body)
                return
            self._write_error(HTTPStatus.NOT_FOUND, "not_found", f"Unknown route: {path}")
        except KeyError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "bad_request", f"Missing required field: {exc}")
        except ValueError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "bad_request", str(exc))
        except json.JSONDecodeError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc))

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _receive_witness(self, body: JSON) -> None:
        """POST /witness (spec §12): accept a peer's countersignature over THIS
        host's store head. The host MUST verify the statement signature AND
        recompute its own head at the witnessed sequence before persisting —
        never store an unverified or non-matching receipt. Persisted WITH the
        leaves snapshot at that sequence (per-leaf retention dispositions)."""
        from . import witnessing
        from .signing import verify_chain_witness

        store = getattr(self.server.chp_host, "store", None)
        if store is None or not hasattr(store, "get_store_head"):
            self._write_error(HTTPStatus.NOT_FOUND, "not_found", "no evidence store")
            return
        my_id = getattr(self.server.chp_host, "host_id",
                        getattr(self.server.chp_host, "_host_id", "unknown"))
        sv = verify_chain_witness(body, expected_host_id=my_id)
        if not sv.valid:
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid_witness",
                              sv.reason or "witness statement failed verification")
            return
        try:
            sequence = int(body.get("sequence"))
        except (TypeError, ValueError):
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid_witness", "bad sequence")
            return
        head = store.get_store_head(at_sequence=sequence)
        if head["store_head"] != body.get("store_head"):
            self._write_error(
                HTTPStatus.CONFLICT, "head_mismatch",
                "statement head does not match this store at that sequence")
            return
        witnessing.record_received(body, head["leaves"])
        self._write_json({"accepted": True, "sequence": sequence,
                          "witness": (body.get("witness") or {}).get("host_id")})

    def _invoke_envelope_of(self, body: JSON) -> tuple[InvocationEnvelope, JSON | None]:
        """Body → envelope with the binding-§2 transport work applied: verified
        caller replaces any asserted subject; a scoped key's out-of-scope
        invocation is a PROCESSED policy_blocked denial (returned second)."""
        envelope_body = dict(body)
        if "correlation_id" in envelope_body and "correlation" not in envelope_body:
            envelope_body["correlation"] = {
                "correlation_id": envelope_body.pop("correlation_id")
            }
        # Bind the VERIFIED caller as the subject — overriding any client-asserted
        # subject — so evidence attributes the action to who actually authenticated,
        # not to whatever the request body claimed. Accountability, not assertion.
        caller = getattr(self, "_caller", None)
        if caller is not None:
            envelope_body["subject"] = {"id": caller, "type": "api_key", "verified": True}
        envelope = InvocationEnvelope.from_mapping(envelope_body)
        scope = getattr(self, "_caller_scope", None)
        if scope is not None and not _scope_allows(scope, envelope.capability_id):
            deny = getattr(self.server.chp_host, "_deny", None)
            if deny is not None:
                from .types import DenialReason
                return envelope, deny(envelope, DenialReason(
                    code="policy_blocked",
                    message=f"capability {envelope.capability_id!r} is outside "
                            f"caller {caller!r}'s key scope",
                    retryable=False,
                )).to_dict()
        return envelope, None

    def _invoke(self, body: JSON) -> JSON:
        envelope, denied = self._invoke_envelope_of(body)
        if denied is not None:
            return denied
        result = asyncio.run(self.server.chp_host.ainvoke_envelope(envelope))
        return result.to_dict()

    def _invoke_stream(self, body: JSON) -> None:
        """mode="stream" over /invoke (binding, proposal 0006): SSE `chunk`
        frames + one terminal `result` frame. A denial (or any outcome decided
        BEFORE the first chunk) is a plain JSON 200 — the response never
        commits to text/event-stream unless the stream actually opens."""
        envelope, denied = self._invoke_envelope_of(body)
        if denied is not None:
            self._write_json(denied)
            return
        host = self.server.chp_host
        if not hasattr(host, "ainvoke_stream"):
            # Router/gateway streaming is a named deferral — degrade to sync.
            result = asyncio.run(host.ainvoke_envelope(envelope))
            self._write_json(result.to_dict())
            return

        agen = host.ainvoke_stream(envelope)
        loop = asyncio.new_event_loop()
        try:
            first = loop.run_until_complete(agen.__anext__())
            if "result" in first:
                # No chunk was produced before the outcome (denial, skip, or a
                # non-generator handler) — answer plain JSON.
                self._write_json(first["result"].to_dict())
                return
            # A real stream: raise the per-connection socket timeout (a slow
            # model can idle past the 30s default) and commit to SSE.
            self.connection.settimeout(600)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            def sse(event: str, data: JSON) -> None:
                self.wfile.write(f"event: {event}\n".encode())
                self.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
                self.wfile.flush()

            sse("chunk", {"delta": first["chunk"]})
            while True:
                try:
                    item = loop.run_until_complete(agen.__anext__())
                except StopAsyncIteration:
                    break
                if "result" in item:
                    sse("result", item["result"].to_dict())
                else:
                    sse("chunk", {"delta": item["chunk"]})
        finally:
            loop.run_until_complete(agen.aclose())
            loop.close()

    # ── Cloud-spill: local-first, cloud-burst ──────────────────────────────
    def _cloud_endpoint(self) -> tuple[str, str] | None:
        """(base_url, api_key) for a cloud OpenAI-compatible endpoint, or None.
        Configured on the gateway via CHP_SPILL_BASE_URL / CHP_SPILL_API_KEY."""
        base = os.environ.get("CHP_SPILL_BASE_URL")
        return (base.rstrip("/"), os.environ.get("CHP_SPILL_API_KEY", "")) if base else None

    def _wants_cloud(self, body: JSON) -> bool:
        """Spill when the caller asks (chp_spill) or the model id is a configured cloud
        model (CHP_SPILL_MODELS) — lets the agent send hard steps to a frontier model."""
        models = {m.strip() for m in (os.environ.get("CHP_SPILL_MODELS") or "").split(",") if m.strip()}
        return bool(body.get("chp_spill") or (models and body.get("model") in models))

    def _spill_sync(self, body: JSON) -> JSON:
        """GOVERNED cloud-spill (proposal 0006): the raw urlopen byte pump is
        gone — spill is an invocation of chp.spill.chat, so it runs the gate
        pipeline and lands on the evidence plane with token accounting. The
        formerly-silent local-failure fallback is now a governed, evidenced
        fallback (a policy that blocks it is the policy working)."""
        logger.info("cloud-spill (governed, non-stream) model=%s", body.get("model"))
        env = InvocationEnvelope.from_mapping({
            "capability_id": "chp.spill.chat",
            "payload": dict(body),
        })
        d = asyncio.run(self.server.chp_host.ainvoke_envelope(env)).to_dict()
        if d.get("outcome") != "success":
            return {"error": {"message": str(d.get("denial") or d.get("error") or "spill failed"),
                              "type": "chp_spill_error"}}
        return (d.get("data") or {}).get("response") or {}

    def _spill_stream(self, body: JSON) -> None:
        """Streaming governed spill: chp.spill.chat in stream mode; the
        upstream's OpenAI chunk objects pass through as SSE, with the
        execution bracket + usage evidence recorded on the host."""
        logger.info("cloud-spill (governed, stream) model=%s", body.get("model"))
        env = InvocationEnvelope.from_mapping({
            "capability_id": "chp.spill.chat",
            "payload": dict(body),
            "mode": "stream",
        })
        agen = self.server.chp_host.ainvoke_stream(env)
        loop = asyncio.new_event_loop()
        sse_open = False
        try:
            while True:
                try:
                    item = loop.run_until_complete(agen.__anext__())
                except StopAsyncIteration:
                    break
                if "result" in item:
                    result = item["result"]
                    if not sse_open:
                        # Denied/failed before any chunk — OpenAI-shaped error.
                        d = result.to_dict()
                        self._write_json({"error": {
                            "message": str(d.get("denial") or d.get("error") or "spill failed"),
                            "type": "chp_spill_error"}})
                        return
                    break
                if not sse_open:
                    self.connection.settimeout(600)
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    sse_open = True
                self.wfile.write(f"data: {json.dumps(item['chunk'])}\n\n".encode())
                self.wfile.flush()
            if sse_open:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
        finally:
            loop.run_until_complete(agen.aclose())
            loop.close()

    def _mlx_chat_call(self, body: JSON) -> JSON:
        """Route an OpenAI chat body through chp.adapters.mlx.chat (capacity-routed +
        evidenced); returns the raw invocation result dict."""
        payload: JSON = {
            "model": body.get("model"),
            "messages": body.get("messages") or [],
            "max_tokens": body.get("max_tokens", 512),
            "temperature": body.get("temperature", 0.7),
        }
        for k in ("top_p", "tools", "tool_choice"):
            if body.get(k) is not None:
                payload[k] = body[k]
        env = InvocationEnvelope.from_mapping({
            "capability_id": "chp.adapters.mlx.chat",
            "payload": payload,
            "metadata": {"prefer": body.get("chp_prefer", "inference")},
        })
        return asyncio.run(self.server.chp_host.ainvoke_envelope(env)).to_dict()

    def _openai_chat(self, body: JSON) -> JSON:
        """Non-streaming OpenAI /v1/chat/completions over the mesh (cloud-spill aware)."""
        cloud = self._cloud_endpoint()
        if cloud and self._wants_cloud(body):
            return self._spill_sync(body)  # explicit spill (governed)
        d = self._mlx_chat_call(body)
        if d.get("outcome") != "success":
            if cloud:  # local failed → governed burst to cloud
                return self._spill_sync(body)
            return {"error": {"message": str(d.get("error") or d.get("denial") or "mlx.chat failed"),
                              "type": "chp_mesh_error"}}
        data = d.get("data") or {}
        import time as _time
        pt, ct = data.get("prompt_tokens", 0), data.get("completion_tokens", 0)
        return {
            "id": d.get("invocation_id") or "chatcmpl-chp",
            "object": "chat.completion",
            "created": int(_time.time()),
            "model": data.get("model") or body.get("model"),
            "choices": [{"index": 0, "message": data.get("message") or {},
                         "finish_reason": data.get("finish_reason") or "stop"}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
        }

    def _openai_chat_stream(self, body: JSON) -> None:
        """Streaming OpenAI shim: mlx.chat is non-streaming, so we compute the full
        completion and emit it as a single SSE chunk sequence (the AI SDK / OpenAI
        clients require SSE when stream=true)."""
        import time as _time
        cloud = self._cloud_endpoint()
        if cloud and self._wants_cloud(body):
            self._spill_stream(body)  # explicit spill (governed)
            return
        d = self._mlx_chat_call(body)
        if d.get("outcome") != "success" and cloud:  # local failed → governed burst
            self._spill_stream(body)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def sse(obj: JSON) -> None:
            self.wfile.write(f"data: {json.dumps(obj)}\n\n".encode())
            self.wfile.flush()

        if d.get("outcome") != "success":
            sse({"error": {"message": str(d.get("error") or d.get("denial") or "mlx.chat failed")}})
            self.wfile.write(b"data: [DONE]\n\n")
            return
        data = d.get("data") or {}
        msg = data.get("message") or {}
        base = {"id": d.get("invocation_id") or "chatcmpl-chp", "object": "chat.completion.chunk",
                "created": int(_time.time()), "model": data.get("model") or body.get("model")}
        sse({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]})
        if msg.get("content"):
            sse({**base, "choices": [{"index": 0, "delta": {"content": msg["content"]}, "finish_reason": None}]})
        if msg.get("tool_calls"):
            tcs = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
            sse({**base, "choices": [{"index": 0, "delta": {"tool_calls": tcs}, "finish_reason": None}]})
        sse({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": data.get("finish_reason") or "stop"}]})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _read_json(self) -> JSON:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        if length < 0 or length > self._MAX_BODY_BYTES:
            # Reject negative (would become read-until-EOF) and oversized bodies
            # before allocating — caught by do_POST and returned as 400.
            raise ValueError(f"request body too large or invalid (Content-Length={length})")
        raw = self.rfile.read(length).decode("utf-8")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _write_json(self, value: JSON, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _write_error(self, status: HTTPStatus, code: str, message: str) -> None:
        self._write_json(
            {
                "error": {
                    "code": code,
                    "message": message,
                }
            },
            status=status,
        )


def create_http_server(
    host: Any,
    *,
    bind: str = "127.0.0.1",
    port: int = 8765,
) -> CapabilityHostHTTPServer:
    """Create, but do not start, a CHP HTTP server.

    *host* may be a ``LocalCapabilityHost`` or a ``MultiHostRouter`` — both
    satisfy the duck-type surface the handler expects.
    """
    # Governed cloud-spill (proposal 0006): when a spill endpoint is configured,
    # the shim's spill paths invoke chp.spill.chat — register it so spill runs
    # the gate pipeline instead of the old ungoverned byte pump.
    if os.environ.get("CHP_SPILL_BASE_URL") and hasattr(host, "register"):
        from .spill import register_spill_capability
        register_spill_capability(host)

    return CapabilityHostHTTPServer((bind, port), host)


def serve_http(
    host: Any,
    *,
    bind: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Serve a CHP host until interrupted.

    *host* may be a ``LocalCapabilityHost`` (single-host) or a
    ``MultiHostRouter`` (gateway mode). For a router, call
    ``asyncio.run(router.connect())`` before calling this function.
    """

    server = create_http_server(host, bind=bind, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


class RemoteCapabilityHost:
    """Client that mirrors the LocalCapabilityHost public API over HTTP.

    Uses only stdlib ``urllib.request`` — zero additional dependencies.
    HTTP 4xx/5xx responses raise ``RuntimeError`` with the JSON error body
    preserved so callers can inspect ``code`` and ``message``.

    Usage::

        remote = RemoteCapabilityHost("http://agent-b.internal:8765")
        result = remote.invoke("data.query", {"q": "..."})
    """

    def __init__(self, base_url: str, *, timeout: int = 30, api_key: str | None = None,
                 retries: int = 0, retry_cap_s: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._api_key = api_key  # never emitted in evidence or logs
        # Opt-in retry (reference feature — the binding's stance stays
        # caller-retries; this is the battery-included caller). Retries
        # `host_unreachable` retryable denials (provably not executed; honors
        # the denial's retry_after_s advice) and ConnectionError (CAVEAT: a
        # mid-flight drop may have executed — at-most-once is not guaranteed
        # on that path; set retries=0 for non-idempotent work). Sleeps
        # min(retry_after_s or 2^attempt, retry_cap_s). Default OFF.
        self._retries = max(0, int(retries))
        self._retry_cap_s = retry_cap_s

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get(self, path: str) -> JSON:
        req = Request(f"{self._base}{path}", method="GET")
        if self._api_key:
            req.add_header("X-CHP-Key", self._api_key)
        return self._send(req)

    def _post(self, path: str, body: JSON) -> JSON:
        raw = json.dumps(body).encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-CHP-Key"] = self._api_key
        req = Request(
            f"{self._base}{path}",
            data=raw,
            headers=headers,
            method="POST",
        )
        return self._send(req)

    def _send(self, req: Request) -> JSON:
        from urllib.error import HTTPError, URLError

        try:
            with urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(body)
            except Exception:
                detail = {"raw": body[:500]}
            if exc.code == 401:
                raise ConnectionError(
                    f"auth rejected by {req.full_url} (check api_key_env config)"
                ) from exc
            raise RuntimeError(f"CHP remote error {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ConnectionError(
                f"CHP remote host unavailable ({self._base}): {exc.reason}"
            ) from exc
        except OSError as exc:
            raise ConnectionError(
                f"CHP remote host connection failed ({self._base}): {exc}"
            ) from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"CHP remote returned non-JSON response: {body[:200]!r}"
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError(
                f"CHP remote returned unexpected response type: {type(data).__name__}"
            )

        return data

    @staticmethod
    def _parse_result(data: JSON) -> InvocationResult:
        denial_raw = data.get("denial")
        denial = (
            DenialReason(
                code=str(denial_raw.get("code", "")),
                message=str(denial_raw.get("message", "")),
                retryable=bool(denial_raw.get("retryable", False)),
                details=dict(denial_raw.get("details") or {}),
            )
            if denial_raw
            else None
        )
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

    # ── public API ────────────────────────────────────────────────────────────

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
        mandate: JSON | None = None,
    ) -> InvocationResult:
        if isinstance(correlation, CorrelationContext):
            corr_dict: JSON = correlation.to_dict()
        else:
            corr_dict = dict(correlation) if correlation else {}
        body: JSON = {
            "capability_id": capability_id,
            "payload": payload or {},
            "mode": mode,
            "correlation": corr_dict,
            "subject": subject or {"id": "remote", "type": "user"},
            "metadata": metadata or {},
        }
        if version is not None:
            body["version"] = version
        if mandate is not None:
            # Presented authority (§10): the delegate host verifies it; the
            # evidence subject becomes "delegate under principal's mandate".
            body["mandate"] = mandate

        attempt = 0
        while True:
            try:
                result = self._parse_result(self._post("/invoke", body))
            except ConnectionError:
                if attempt >= self._retries:
                    raise
                self._retry_sleep(attempt, None)
                attempt += 1
                continue
            denial = result.denial
            if (denial is not None and denial.code == "host_unreachable"
                    and denial.retryable and attempt < self._retries):
                # A host_unreachable denial provably never executed (§11) —
                # the safe retry, paced by the intermediary's own advice.
                retry_after = (denial.details or {}).get("retry_after_s")
                self._retry_sleep(attempt, retry_after)
                attempt += 1
                continue
            return result

    def _retry_sleep(self, attempt: int, retry_after_s) -> None:
        import time as _time

        base = float(retry_after_s) if isinstance(retry_after_s, (int, float)) else float(2 ** attempt)
        _time.sleep(min(base, self._retry_cap_s))

    def invoke(
        self,
        capability_id: str,
        payload: JSON | None = None,
        **kwargs: Any,
    ) -> InvocationResult:
        return asyncio.run(self.ainvoke(capability_id, payload, **kwargs))

    def invoke_envelope(self, envelope: InvocationEnvelope) -> InvocationResult:
        """Invoke from a pre-built envelope (synchronous; mirrors the server's /invoke)."""
        data = self._post("/invoke", envelope.to_dict())
        return self._parse_result(data)

    def invoke_stream(self, capability_id: str, payload: JSON | None = None, *,
                      version: str | None = None,
                      correlation: "CorrelationContext | JSON | None" = None,
                      subject: JSON | None = None,
                      metadata: JSON | None = None,
                      mandate: JSON | None = None,
                      timeout: int = 600):
        """Streaming invocation (binding, proposal 0006): a GENERATOR yielding
        chunk deltas; its return value (``StopIteration.value``, or capture via
        ``yield from``) is the terminal :class:`InvocationResult`. A denial —
        or any host without streaming — arrives as a plain JSON response and is
        returned immediately with no chunks."""
        if isinstance(correlation, CorrelationContext):
            corr_dict: JSON = correlation.to_dict()
        else:
            corr_dict = dict(correlation) if correlation else {}
        body: JSON = {
            "capability_id": capability_id,
            "payload": payload or {},
            "mode": "stream",
            "correlation": corr_dict,
            "subject": subject or {"id": "remote", "type": "user"},
            "metadata": metadata or {},
        }
        if version is not None:
            body["version"] = version
        if mandate is not None:
            body["mandate"] = mandate

        raw = json.dumps(body).encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-CHP-Key"] = self._api_key
        req = Request(f"{self._base}/invoke", data=raw, headers=headers, method="POST")
        resp = urlopen(req, timeout=timeout)
        content_type = resp.headers.get("Content-Type", "")
        if "text/event-stream" not in content_type:
            # The outcome was decided before any chunk (denial/skip/sync host).
            return self._parse_result(json.loads(resp.read().decode("utf-8")))

        event: str | None = None
        result: InvocationResult | None = None
        for raw_line in resp:
            line = raw_line.decode("utf-8").rstrip("\n")
            if line.startswith("event: "):
                event = line[len("event: "):].strip()
            elif line.startswith("data: "):
                data = json.loads(line[len("data: "):])
                if event == "result":
                    result = self._parse_result(data)
                    break
                yield data.get("delta")
        if result is None:
            raise ConnectionError("stream ended without a terminal result frame")
        return result

    def discover(self, **filter_kwargs: Any) -> JSON:
        """Return the host descriptor, optionally filtering capabilities."""
        descriptor = self._get("/host")
        if not filter_kwargs:
            return descriptor
        caps = descriptor.get("capabilities", [])
        for key, val in filter_kwargs.items():
            caps = [c for c in caps if c.get(key) == val]
        return {**descriptor, "capabilities": caps}

    def replay(self, correlation_id: str) -> list[JSON]:
        """Return the evidence events list for *correlation_id*."""
        result = self._get(f"/replay/{correlation_id}")
        return list(result.get("events", []))

    def replay_result(self, query: "str | ReplayQuery | JSON") -> JSON:
        """Replay by correlation ID (str) or a ReplayQuery object/dict."""
        if isinstance(query, str):
            return self._get(f"/replay/{query}")
        if isinstance(query, ReplayQuery):
            return self._post("/replay", query.to_dict())
        return self._post("/replay", dict(query))

    def health(self) -> JSON:
        """Return the /health response from the remote host."""
        return self._get("/health")

    def identity(self) -> JSON:
        """The host's public identity document (spec §3.1 — unauthenticated)."""
        return self._get("/.well-known/chp-identity")

    def export_bundle(self, correlation_id: str) -> JSON:
        """The host's (signed when keyed) evidence bundle for a correlation."""
        return self._get(f"/export/{correlation_id}")

    def verify(self, correlation_id: str) -> JSON:
        """Return the SHA256 chain verification result for *correlation_id*.

        Shape mirrors ``ChainVerificationResult``: ``correlation_id``,
        ``event_count``, ``verified_count``, ``unverified_count``, ``valid``,
        ``first_broken_sequence``.
        """
        return self._get(f"/verify/{correlation_id}")
