"""CHP over Zenoh — a non-HTTP transport binding (spec/chp-zenoh-binding.md).

A ``ZenohTransport`` satisfies the same ``chp_core.transport.Transport`` protocol as the HTTP
transport, so the router composes it with zero changes; a ``ZenohHostServer`` serves a
``LocalCapabilityHost`` over Zenoh query/reply. The wire OBJECTS are unchanged — the same
``InvocationEnvelope`` / ``InvocationResult`` JSON the HTTP binding carries — only the CARRIER differs
(Zenoh key-expression query/reply + pub/sub). This package pulls the heavy ``eclipse-zenoh`` dependency
so ``chp-core`` stays dependency-free.

The binding is split into focused modules so new Zenoh features compose without bloating the core:

- ``keys``     — the key-expression layout (RPC keys + pub/sub keys).
- ``wire``     — the shared (de)serialization codec.
- ``session``  — session lifecycle (open/own).
- ``pubsub``   — a reusable ``Stream`` (the async carrier: evidence, decisions).
- ``presence`` — liveliness-based ``Presence`` (push-based host up/down).
- ``client``   — ``ZenohTransport`` (the client side).
- ``server``   — ``ZenohHostServer`` (the queryable/host side).
"""

from __future__ import annotations

from .client import ZenohTransport
from .keys import KEY_PREFIX, keys, presence_glob
from .presence import Presence
from .pubsub import Stream
from .server import ZenohHostServer
from .wire import first_reply, result_from_dict

__all__ = ["KEY_PREFIX", "keys", "presence_glob", "ZenohTransport", "ZenohHostServer",
           "result_from_dict", "first_reply", "Stream", "Presence"]
