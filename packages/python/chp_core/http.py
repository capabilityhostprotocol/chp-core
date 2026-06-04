"""Small HTTP surface for serving a local CHP host."""

from __future__ import annotations

import asyncio
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse

from .host import LocalCapabilityHost
from .types import InvocationEnvelope, JSON, ReplayQuery


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
