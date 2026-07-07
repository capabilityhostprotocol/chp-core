"""HttpAdapter — governed HTTP client as a CHP capability.

Safety invariants (MUST PRESERVE):
* Every URL's origin (scheme + host) must match an entry in ``allowed_origins``
  if the list is non-None.
* Request header VALUES never in evidence (may contain ``Authorization``).
* Response body never in evidence (may contain PII/credentials); only
  ``body_length`` and ``content_type`` are recorded.
* Fresh ``httpx.AsyncClient`` per call — loop-safe, no connection reuse issues.

One capability: ``request``
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import time as _time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

# Cloud metadata / link-local endpoints — never a legitimate HTTP target, the
# primary SSRF escalation. Blocked by default even without an allowlist. Does
# NOT include general loopback/RFC-1918/CGNAT: this adapter legitimately calls
# localhost sovereign inference (vLLM/TEI/scout) and Tailscale 100.64/10 mesh
# nodes — set block_private_networks=True to sandbox those too.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",   # AWS/GCP/Azure IMDS
    "169.254.170.2",     # ECS task metadata
    "fd00:ec2::254",     # EC2 IMDSv2 IPv6
    "metadata.google.internal",
    "metadata",
})

from chp_core import BaseAdapter, capability

_EMITS = ["http_request", "http_response", "http_error", "http_circuit_open"]

_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


@dataclass
class HttpConfig:
    """Config for HttpAdapter.

    ``allowed_origins`` — if non-None, every URL must start with one of these
    origin strings (``scheme://host[:port]``). Use to sandbox the adapter to
    known hosts.

    ``default_headers`` — merged with per-request headers (request wins on conflict).

    ``transport`` accepts an ``httpx.MockTransport`` for tests.
    """

    allowed_origins: list[str] | None = None
    default_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    max_response_bytes: int = 1 * 1024 * 1024  # 1 MB
    transport: Any = None
    # When True, additionally deny loopback / private / link-local / CGNAT
    # targets (resolving hostnames first). Off by default because sovereign
    # inference (localhost) and mesh (Tailscale 100.64/10) depend on them.
    block_private_networks: bool = False
    # Resilience: retries + circuit breaker key off TRANSPORT failures (server
    # down, connection refused, timeout) — NOT HTTP status codes (those return
    # normally as before). Composing adapters (tei/vllm/github/local_llm) inherit
    # this for free.
    max_retries: int = 2            # extra attempts after the first, on transport error
    backoff_base: float = 0.3       # seconds; delay = backoff_base * 2**attempt
    circuit_threshold: int = 5      # consecutive transport failures (per origin) to open
    circuit_cooldown: float = 30.0  # seconds the circuit stays open, failing fast

    def _check_url(self, url: str) -> str:
        """Return the URL unchanged if allowed; raise PermissionError if not."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        # 1. Always deny cloud metadata endpoints (SSRF crown jewel).
        if host in _METADATA_HOSTS:
            raise PermissionError(f"host {host!r} is a blocked metadata endpoint")

        # 2. Optional strict sandbox: deny loopback/private/link-local/CGNAT.
        if self.block_private_networks:
            for addr in self._resolve_ips(host, parsed.port):
                if (
                    addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast
                ):
                    raise PermissionError(f"host {host!r} resolves to blocked address {addr}")

        # 3. Origin allowlist — strict scheme+host[:port] equality (no prefix
        #    match: 'https://evil.com' must not admit 'https://evil.com.attacker').
        if self.allowed_origins is not None:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            allowed_set = {a.rstrip("/") for a in self.allowed_origins}
            if origin not in allowed_set:
                raise PermissionError(f"URL origin {origin!r} is not in allowed_origins")
        return url

    @staticmethod
    def _resolve_ips(host: str, port: int | None) -> list[ipaddress._BaseAddress]:
        """Resolve host to IPs. A bare IP literal skips DNS. Unresolvable hosts
        raise (fail-closed) only in strict mode where this is called."""
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, port or 80, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise PermissionError(f"host {host!r} could not be resolved") from exc
        return [ipaddress.ip_address(info[4][0]) for info in infos]


class HttpAdapter(BaseAdapter):
    """Generic governed HTTP client."""

    adapter_id = "chp.adapters.http"
    adapter_name = "HTTP"
    adapter_description = "Make governed HTTP requests with optional URL origin allowlist."
    adapter_category = "execution"
    adapter_tags = ["http", "client", "api", "execution"]

    def __init__(self, config: HttpConfig | None = None) -> None:
        self._config = config or HttpConfig()
        # Per-origin circuit state: {origin: {"failures": int, "opened_until": monotonic}}
        self._circuit: dict[str, dict[str, float]] = {}
        self._circuit_lock = threading.Lock()

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _circuit_is_open(self, origin: str) -> bool:
        with self._circuit_lock:
            st = self._circuit.get(origin)
            return bool(st and st["opened_until"] > _time.monotonic())

    def _circuit_record(self, origin: str, *, success: bool) -> None:
        with self._circuit_lock:
            st = self._circuit.setdefault(origin, {"failures": 0.0, "opened_until": 0.0})
            if success:
                st["failures"] = 0.0
                st["opened_until"] = 0.0
            else:
                st["failures"] += 1
                if st["failures"] >= self._config.circuit_threshold:
                    st["opened_until"] = _time.monotonic() + self._config.circuit_cooldown

    @capability(
        id="chp.adapters.http.request",
        version="1.0.0",
        description="Make an HTTP request.",
        category="execution",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": list(_ALLOWED_METHODS),
                    "description": "HTTP method.",
                },
                "url": {"type": "string", "description": "Full URL to request."},
                "headers": {
                    "type": "object",
                    "description": "Additional request headers.",
                    "additionalProperties": {"type": "string"},
                },
                "body": {"type": "string", "description": "Plain-text request body."},
                "json_body": {"description": "JSON request body (serialized as application/json)."},
                "params": {
                    "type": "object",
                    "description": "URL query parameters.",
                    "additionalProperties": {"type": "string"},
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Per-request timeout override (seconds).",
                },
            },
            "required": ["method", "url"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["http", "client"],
    )
    async def request(self, ctx: Any, payload: dict) -> dict:
        method = payload["method"].upper()
        url = payload["url"]
        req_headers = payload.get("headers") or {}
        body = payload.get("body")
        json_body = payload.get("json_body")
        params = payload.get("params") or {}
        timeout = float(payload.get("timeout") or self._config.timeout)

        # URL allowlist check
        try:
            self._config._check_url(url)
        except PermissionError as exc:
            ctx.emit("http_error", {
                "reason": "url_not_allowed",
                "url": url,
                "error": str(exc),
            }, redacted=False)
            raise

        # Merge headers: default first, then per-request
        merged_headers = {**self._config.default_headers, **req_headers}

        ctx.emit("http_request", {
            "method": method,
            "url": url,
            "header_keys": sorted(merged_headers.keys()),
            # header values intentionally not recorded
            "has_body": body is not None or json_body is not None,
            "param_keys": sorted(params.keys()),
        }, redacted=False)

        # Circuit breaker: fail fast if this origin is currently tripped.
        origin = self._origin(url)
        if self._circuit_is_open(origin):
            ctx.emit("http_circuit_open", {
                "method": method, "url": url, "origin": origin,
            }, redacted=False)
            raise RuntimeError(f"circuit open for {origin!r} — failing fast (recent transport failures)")

        t0 = _time.monotonic()
        attempts = self._config.max_retries + 1
        resp = None
        for attempt in range(attempts):
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    transport=self._config.transport,
                ) as client:
                    resp = await client.request(
                        method,
                        url,
                        headers=merged_headers or None,
                        content=body.encode() if body else None,
                        json=json_body,
                        params=params or None,
                    )
                self._circuit_record(origin, success=True)
                break
            except httpx.HTTPError as exc:
                if attempt + 1 < attempts:
                    await asyncio.sleep(self._config.backoff_base * (2 ** attempt))
                    continue
                self._circuit_record(origin, success=False)
                duration_ms = int((_time.monotonic() - t0) * 1000)
                ctx.emit("http_error", {
                    "method": method,
                    "url": url,
                    "reason": type(exc).__name__,
                    "error": str(exc)[:200],
                    "attempts": attempt + 1,
                    "duration_ms": duration_ms,
                }, redacted=False)
                raise

        duration_ms = int((_time.monotonic() - t0) * 1000)

        raw_bytes = resp.content
        truncated = len(raw_bytes) > self._config.max_response_bytes
        if truncated:
            raw_bytes = raw_bytes[: self._config.max_response_bytes]

        content_type = resp.headers.get("content-type", "")
        body_str = raw_bytes.decode(errors="replace")

        # Attempt JSON parse
        json_data = None
        if "json" in content_type:
            try:
                import json as _json
                json_data = _json.loads(raw_bytes)
            except Exception:
                json_data = None  # best-effort parse; leave None on malformed JSON

        # Extract token usage from OpenAI-compatible responses (usage{} key)
        _usage = json_data.get("usage") if isinstance(json_data, dict) else None
        _model = (
            (json_data.get("model") if isinstance(json_data, dict) else None)
            or (json_body or {}).get("model")
        )

        ctx.emit("http_response", {
            "method": method,
            "url": str(resp.url),
            "status_code": resp.status_code,
            "content_type": content_type,
            "body_length": len(resp.content),
            "truncated": truncated,
            "duration_ms": duration_ms,
            # body not recorded
            **({
                "prompt_tokens": _usage.get("prompt_tokens", 0),
                "completion_tokens": _usage.get("completion_tokens", 0),
                "total_tokens": (
                    _usage.get("total_tokens")
                    or _usage.get("prompt_tokens", 0) + _usage.get("completion_tokens", 0)
                ),
                "model": _model or "unknown",
            } if _usage else {}),
        }, redacted=False)

        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_str,
            "json": json_data,
            "content_type": content_type,
            "url": str(resp.url),
            "duration_ms": duration_ms,
        }
