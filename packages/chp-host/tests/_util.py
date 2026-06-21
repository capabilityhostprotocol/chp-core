"""Shared test helpers: build small hosts and serve them on ephemeral ports."""

from __future__ import annotations

import contextlib
import threading
import time

from chp_core import (
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    capability,
    create_http_server,
)


def make_echo_host(host_id: str, tag: str, cap_id: str = "echo.who") -> LocalCapabilityHost:
    """A host with one capability that returns which host served it."""

    @capability(id=cap_id, version="1.0.0", description="Report the serving host.")
    def who() -> dict:  # type: ignore[return-value]
        return {"host": tag}

    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))
    host.register(who)
    return host


def make_math_host(host_id: str = "math-host") -> LocalCapabilityHost:
    """A host with a single ``math.add`` capability (schema-validated)."""

    @capability(
        id="math.add",
        version="1.0.0",
        description="Add two numbers.",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
        },
    )
    def add(a: float, b: float) -> dict:  # type: ignore[return-value]
        return {"sum": a + b}

    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))
    host.register(add)
    return host


@contextlib.contextmanager
def served(host: LocalCapabilityHost):
    """Serve *host* over HTTP on an ephemeral port; yield its base URL."""
    server = create_http_server(host, bind="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        time.sleep(0.15)  # let the listener come up
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
