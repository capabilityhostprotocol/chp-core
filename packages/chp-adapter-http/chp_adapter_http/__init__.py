"""chp-adapter-http — governed HTTP client as a CHP capability.

Capabilities:

* ``request`` — make an HTTP request with optional URL origin allowlist.
  Request header values and response body absent from evidence.
* ``stream`` — stream an SSE/chunked response and collect it (server streams,
  the cap returns the parsed events + aggregated text). Same safety invariants;
  event content absent from evidence.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_http import HttpAdapter, HttpConfig

    host = LocalCapabilityHost()
    register_adapter(host, HttpAdapter(HttpConfig(
        allowed_origins=["https://api.example.com"],
    )))
"""

from __future__ import annotations

from .adapter import HttpAdapter, HttpConfig

__all__ = ["HttpAdapter", "HttpConfig"]
