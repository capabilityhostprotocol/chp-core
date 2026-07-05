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


def _host_assurance(host_id: str | None = None) -> JSON:
    """Declared evidence assurance tier for this host (v0.2). `signed` when a
    host keypair is present, else `hash-chain` (the store always chains).
    Verifiers reject a lower-than-expected tier rather than degrade silently.

    A signed host also serves its self-signed `host_identity` attestation so a
    mesh peer can verify the key self-attests this host_id *before* pinning it
    (chp-v0.2.md §3) — not blindly trust whatever /host reports."""
    try:
        from .signing import load_host_key
        key = load_host_key()
    except Exception:
        key = None
    if key is None:
        return {"assurance": "hash-chain"}
    out: JSON = {"assurance": "signed", "key_id": key.key_id, "public_key": key.public_key_b64}
    if host_id and key.can_sign:
        try:
            from .signing import build_attestation
            from .types import utc_now
            out["host_identity"] = build_attestation(host_id, key, valid_from=utc_now())
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
        """
        self._caller: str | None = None
        presented = self.headers.get("X-CHP-Key", "")
        named = os.environ.get("CHP_HOST_API_KEYS")
        shared = os.environ.get("CHP_HOST_API_KEY")

        if named:
            for entry in named.split(","):
                name, sep, k = entry.partition(":")
                if sep and hmac.compare_digest(presented, k.strip()):
                    self._caller = name.strip()
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
                "version": "0.1",
                "host_version": _host_version(),
            })
            return
        if not self._check_auth():
            return
        if path == "/host":
            desc = self._sync_discover()
            desc.setdefault("host_version", _host_version())
            host_id = desc.get("id") or (desc.get("hosts") or [None])[0]
            for k, v in _host_assurance(host_id).items():
                desc.setdefault(k, v)
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
            if not hasattr(self.server.chp_host, "store"):
                self._write_json({
                    "note": "Verification not available in gateway mode — evidence is distributed.",
                    "correlation_id": correlation_id,
                    "hosts": list(getattr(self.server.chp_host, "_descriptors", {}).keys()),
                })
                return
            result = self.server.chp_host.store.verify_chain(correlation_id)
            self._write_json(asdict(result))
            return
        if path == "/metrics":
            self._write_metrics()
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
        body = (
            format_prometheus(report).encode("utf-8")
            + b"\n"
            + format_token_prometheus(token_report).encode("utf-8")
        )
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
            self._write_error(HTTPStatus.NOT_FOUND, "not_found", f"Unknown route: {path}")
        except KeyError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "bad_request", f"Missing required field: {exc}")
        except ValueError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "bad_request", str(exc))
        except json.JSONDecodeError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc))

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _invoke(self, body: JSON) -> JSON:
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
        result = asyncio.run(self.server.chp_host.ainvoke_envelope(envelope))
        return result.to_dict()

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

    def _proxy_body(self, body: JSON) -> bytes:
        clean = {k: v for k, v in body.items() if not k.startswith("chp_")}
        return json.dumps(clean).encode()

    def _proxy_json(self, body: JSON, cloud: tuple[str, str]) -> JSON:
        base, key = cloud
        logger.info("cloud-spill (non-stream) → %s model=%s", base, body.get("model"))
        req = Request(f"{base}/chat/completions", data=self._proxy_body(body),
                      headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
                      method="POST")
        with urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode())

    def _proxy_stream(self, body: JSON, cloud: tuple[str, str]) -> None:
        base, key = cloud
        logger.info("cloud-spill (stream) → %s model=%s", base, body.get("model"))
        stream_body = {k: v for k, v in body.items() if not k.startswith("chp_")}
        stream_body["stream"] = True
        req = Request(f"{base}/chat/completions", data=json.dumps(stream_body).encode(),
                      headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
                      method="POST")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        with urlopen(req, timeout=180) as resp:
            for line in resp:  # pass the cloud SSE through verbatim
                self.wfile.write(line)
                self.wfile.flush()

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
            return self._proxy_json(body, cloud)  # explicit spill
        d = self._mlx_chat_call(body)
        if d.get("outcome") != "success":
            if cloud:  # local failed → burst to cloud
                return self._proxy_json(body, cloud)
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
            self._proxy_stream(body, cloud)  # explicit spill
            return
        d = self._mlx_chat_call(body)
        if d.get("outcome") != "success" and cloud:  # local failed → burst to cloud
            self._proxy_stream(body, cloud)
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

    def __init__(self, base_url: str, *, timeout: int = 30, api_key: str | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._api_key = api_key  # never emitted in evidence or logs

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
        data = self._post("/invoke", body)
        return self._parse_result(data)

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

    def verify(self, correlation_id: str) -> JSON:
        """Return the SHA256 chain verification result for *correlation_id*.

        Shape mirrors ``ChainVerificationResult``: ``correlation_id``,
        ``event_count``, ``verified_count``, ``unverified_count``, ``valid``,
        ``first_broken_sequence``.
        """
        return self._get(f"/verify/{correlation_id}")
