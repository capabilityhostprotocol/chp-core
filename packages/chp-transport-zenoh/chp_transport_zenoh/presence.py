"""Liveliness-based presence — push-based host up/down over Zenoh.

A CHP host declares a liveliness TOKEN at its presence key; the moment that token drops (process death,
disconnect, network partition) Zenoh notifies watchers instantly — no heartbeat polling, no TTL guess,
no staleness sweep. A fleet watcher subscribes to the presence glob and gets ``on_change(host_key,
alive)`` per host, or queries the currently-live set on demand. (chp-zenoh-binding.md §4.)
"""

from __future__ import annotations

from typing import Any, Callable


class Presence:
    """Declare / watch / query Zenoh liveliness for CHP host presence.

    ``declare(key)`` marks this host alive (returns a token; ``.undeclare()`` or drop = down).
    ``watch(key_expr, on_change)`` fires ``on_change(key, alive)`` — alive=True on a token appearing,
    False on it dropping — over a key-expression (use ``keys.presence_glob()`` for the whole fleet).
    ``query(key_expr)`` returns the currently-live keys.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    def declare(self, key: str) -> Any:
        """Declare this host ALIVE at ``key``. Returns a ``LivelinessToken`` — hold it; when it is
        undeclared or the process dies, watchers see the host go down."""
        return self._session.liveliness().declare_token(key)

    def watch(self, key_expr: str, on_change: Callable[[str, bool], None], *,
              history: bool = True) -> Any:
        """Subscribe to liveliness changes under ``key_expr``. ``history=True`` replays the tokens
        already live at subscribe time (so a late watcher learns the current fleet). Returns the Zenoh
        subscriber — keep a reference; ``.undeclare()`` to stop."""
        import zenoh

        def _on_sample(sample: Any) -> None:
            alive = sample.kind == zenoh.SampleKind.PUT      # PUT = token appeared; DELETE = dropped
            on_change(str(sample.key_expr), alive)
        return self._session.liveliness().declare_subscriber(
            key_expr, _on_sample, history=history)

    def query(self, key_expr: str, *, timeout: float = 5.0) -> list[str]:
        """The CURRENTLY-live keys under ``key_expr`` (a one-shot liveliness get)."""
        live: list[str] = []
        for reply in self._session.liveliness().get(key_expr, timeout=timeout):
            ok = getattr(reply, "ok", None)
            if ok is not None:
                live.append(str(ok.key_expr))
        return live
