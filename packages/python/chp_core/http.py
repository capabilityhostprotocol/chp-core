"""Small HTTP surface for serving a local CHP host and a client for remote hosts."""

from __future__ import annotations

import asyncio
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

from .host import LocalCapabilityHost
from .types import (
    CorrelationContext,
    DenialReason,
    InvocationEnvelope,
    InvocationResult,
    JSON,
    ReplayQuery,
)


class CapabilityHostHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server bound to a LocalCapabilityHost."""

    def __init__(self, server_address: tuple[str, int], host: LocalCapabilityHost) -> None:
        super().__init__(server_address, CapabilityHostRequestHandler)
        self.chp_host = host


class CapabilityHostRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON API for CHP v0.1 discovery, invocation, and replay."""

    server: CapabilityHostHTTPServer

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/" or path == "/health":
            host_desc = self.server.chp_host.discover()
            cap_count = len(host_desc.get("capabilities", []))
            self._write_json({
                "status": "ok",
                "host_id": host_desc.get("id", "unknown"),
                "protocol": "chp",
                "version": "0.1",
                "capability_count": cap_count,
            })
            return
        if path == "/host":
            self._write_json(self.server.chp_host.discover())
            return
        if path == "/capabilities":
            self._write_json({"capabilities": self.server.chp_host.discover()["capabilities"]})
            return
        if path.startswith("/replay/"):
            correlation_id = unquote(path.removeprefix("/replay/"))
            self._write_json(self.server.chp_host.replay_result(correlation_id).to_dict())
            return
        self._write_error(HTTPStatus.NOT_FOUND, "not_found", f"Unknown route: {path}")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._read_json()
            if path == "/invoke":
                self._write_json(self._invoke(body))
                return
            if path == "/replay":
                query = ReplayQuery.from_mapping(body)
                self._write_json(self.server.chp_host.replay_result(query).to_dict())
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
    host: LocalCapabilityHost,
    *,
    bind: str = "127.0.0.1",
    port: int = 8765,
) -> CapabilityHostHTTPServer:
    """Create, but do not start, a CHP HTTP server."""

    return CapabilityHostHTTPServer((bind, port), host)


def serve_http(
    host: LocalCapabilityHost,
    *,
    bind: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Serve a CHP host until interrupted."""

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

    def __init__(self, base_url: str, *, timeout: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get(self, path: str) -> JSON:
        req = Request(f"{self._base}{path}", method="GET")
        return self._send(req)

    def _post(self, path: str, body: JSON) -> JSON:
        raw = json.dumps(body).encode("utf-8")
        req = Request(
            f"{self._base}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
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
