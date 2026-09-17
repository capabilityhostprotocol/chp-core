"""Reusable Zenoh pub/sub Stream — the async carrier for CHP's event streams.

Generalizes the one-off evidence pub/sub into a NAMED channel over a key-expression, so new async
streams (the evidence stream, and additively the async HITL decision stream) don't each re-implement
put/subscribe. Carrier-only: it moves JSON objects, it holds no CHP semantics. This is the seam new
Zenoh pub/sub features plug into.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from chp_core.types import JSON


class Stream:
    """A named publish/subscribe channel over a Zenoh key-expression.

    ``publish(obj)`` puts a JSON object; ``subscribe(cb)`` declares a subscriber that decodes each
    sample and hands ``cb`` the dict. ``subscribe`` returns the Zenoh subscriber — keep a reference and
    call ``.undeclare()`` to stop. A ``key_expr`` (with wildcards) may be passed to ``subscribe`` to
    listen across many hosts' streams at once.
    """

    def __init__(self, session: Any, key: str) -> None:
        self._session = session
        self.key = key

    def publish(self, obj: JSON) -> None:
        self._session.put(self.key, json.dumps(obj).encode())

    def subscribe(self, callback: Callable[[JSON], None], *, key_expr: str | None = None) -> Any:
        def _on_sample(sample: Any) -> None:
            callback(json.loads(bytes(sample.payload)))
        return self._session.declare_subscriber(key_expr or self.key, _on_sample)
