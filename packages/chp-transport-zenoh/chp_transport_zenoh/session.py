"""Zenoh session lifecycle helper — shared by the client transport and the host server."""

from __future__ import annotations

from typing import Any


def open_session(session: Any, config: Any) -> tuple[Any, bool]:
    """Return (session, owns_it). A caller MAY pass an existing session (shared across
    transports/servers/features); else open one from ``config`` (default peer)."""
    if session is not None:
        return session, False
    import zenoh
    return zenoh.open(config if config is not None else zenoh.Config()), True
