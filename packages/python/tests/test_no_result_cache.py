"""A capability may opt its result OUT of the §13 replay cache via descriptor
metadata {"cache_results": False} — so a sensitive return (secrets.get's
{"value": <token>}) is never persisted at rest in invocation_results. (rad:3d5b718)"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.host import lookup_recorded_result

SECRET = "SECRET-TOKEN-must-not-persist"


def _host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("no-cache-host", store=SQLiteEvidenceStore(":memory:"))
    calls = {"sensitive": 0, "plain": 0}

    async def sensitive(_ctx, _payload):
        calls["sensitive"] += 1
        return {"value": SECRET, "n": calls["sensitive"]}

    async def plain(_ctx, payload):
        calls["plain"] += 1
        return {"echo": payload.get("value"), "n": calls["plain"]}

    host.register(
        CapabilityDescriptor(id="sensitive.get", version="1.0.0", description=".",
                             metadata={"cache_results": False}),
        sensitive)
    host.register(CapabilityDescriptor(id="plain.echo", version="1.0.0", description="."), plain)
    host._test_calls = calls  # type: ignore[attr-defined]
    return host


class NoResultCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_result_never_cached_and_reexecutes(self) -> None:
        host = _host()
        env = {"capability_id": "sensitive.get", "payload": {},
               "invocation_id": "inv_sensitive_1"}
        first = await host.ainvoke_envelope(dict(env))
        second = await host.ainvoke_envelope(dict(env))

        self.assertEqual(first.outcome, "success")
        self.assertFalse(first.replayed)
        # No cache → a repeated invocation_id RE-EXECUTES (never replays a stored value)
        self.assertFalse(second.replayed)
        self.assertEqual(host._test_calls["sensitive"], 2)
        # …and nothing was written to the §13 store for it: the secret is not at rest.
        self.assertIsNone(lookup_recorded_result(host.store, "inv_sensitive_1"))

    async def test_plain_result_still_cached_and_replays(self) -> None:
        host = _host()
        env = {"capability_id": "plain.echo", "payload": {"value": "hi"},
               "invocation_id": "inv_plain_1"}
        first = await host.ainvoke_envelope(dict(env))
        second = await host.ainvoke_envelope(dict(env))
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)  # default caching intact for ordinary caps
        self.assertEqual(host._test_calls["plain"], 1)
        self.assertIsNotNone(lookup_recorded_result(host.store, "inv_plain_1"))


if __name__ == "__main__":
    unittest.main()
