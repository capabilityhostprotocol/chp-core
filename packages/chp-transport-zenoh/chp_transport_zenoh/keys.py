"""Zenoh key-expression layout for a CHP host (chp-zenoh-binding.md §2)."""

from __future__ import annotations

KEY_PREFIX = "chp/v1"


def keys(host_id: str, *, prefix: str = KEY_PREFIX) -> dict[str, str]:
    """The Zenoh key-expression table for a host (chp-zenoh-binding.md §2).

    ``invoke``/``declarations``/``replay``/``export``/``health`` are query/reply (RPC) keys;
    ``evidence``/``presence``/``decisions`` are pub/sub keys (async streams that ride Zenoh
    publish/subscribe rather than a blocking query). ``presence`` carries the host's liveliness
    token; ``decisions`` carries the async HITL approval-decision stream.
    """
    return {
        "invoke": f"{prefix}/invocations/{host_id}/requests",
        "declarations": f"{prefix}/capabilities/{host_id}/declarations",
        "replay": f"{prefix}/replay/{host_id}/requests",
        "export": f"{prefix}/export/{host_id}/requests",
        "health": f"{prefix}/health/{host_id}",
        "evidence": f"{prefix}/evidence/{host_id}/stream",
        "presence": f"{prefix}/presence/{host_id}",
        "decisions": f"{prefix}/decisions/{host_id}/stream",
    }


def presence_glob(prefix: str = KEY_PREFIX) -> str:
    """A key-expression matching EVERY host's presence token — what a fleet watcher subscribes to
    for push-based node up/down across the mesh (`chp/v1/presence/*`)."""
    return f"{prefix}/presence/*"
