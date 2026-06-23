"""Small HTTP surface for serving a local CHP host and a client for remote hosts."""

from __future__ import annotations

import asyncio
import inspect
import json
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


class CapabilityHostHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server bound to a CHP host (LocalCapabilityHost or MultiHostRouter)."""

    def __init__(self, server_address: tuple[str, int], host: Any) -> None:
        super().__init__(server_address, CapabilityHostRequestHandler)
        self.chp_host = host


class CapabilityHostRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON API for CHP v0.1 discovery, invocation, and replay."""

    server: CapabilityHostHTTPServer

    def _check_auth(self) -> bool:
        """Return True if the request is authorized (or auth is not configured)."""
        key = os.environ.get("CHP_HOST_API_KEY")
        if not key:
            return True
        if self.headers.get("X-CHP-Key") == key:
            return True
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
            cap_count = len(host_desc.get("capabilities", []))
            self._write_json({
                "status": "ok",
                "host_id": host_desc.get("id") or host_desc.get("hosts", ["unknown"])[0],
                "protocol": "chp",
                "version": "0.1",
                "host_version": _host_version(),
                "capability_count": cap_count,
            })
            return
        if not self._check_auth():
            return
        if path == "/host":
            desc = self._sync_discover()
            desc.setdefault("host_version", _host_version())
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
        envelope = InvocationEnvelope.from_mapping(envelope_body)
        result = asyncio.run(self.server.chp_host.ainvoke_envelope(envelope))
        return result.to_dict()

    def _openai_chat(self, body: JSON) -> JSON:
        """Translate an OpenAI /v1/chat/completions request to chp.adapters.mlx.chat
        (routed by the host/router — capacity-aware + evidenced) and back."""
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
        result = asyncio.run(self.server.chp_host.ainvoke_envelope(env))
        d = result.to_dict()
        if d.get("outcome") != "success":
            return {"error": {"message": str(d.get("error") or d.get("denial") or "mlx.chat failed"),
                              "type": "chp_mesh_error"}}
        data = d.get("data") or {}
        pt, ct = data.get("prompt_tokens", 0), data.get("completion_tokens", 0)
        return {
            "id": d.get("invocation_id") or "chatcmpl-chp",
            "object": "chat.completion",
            "model": data.get("model") or payload["model"],
            "choices": [{"index": 0, "message": data.get("message") or {},
                         "finish_reason": data.get("finish_reason") or "stop"}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
        }

    def _read_json(self) -> JSON:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
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
