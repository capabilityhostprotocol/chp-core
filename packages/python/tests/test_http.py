from __future__ import annotations

import json
import sys
import threading
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (  # noqa: E402
    CapabilityDescriptor,
    LocalCapabilityHost,
    RemoteCapabilityHost,
    SQLiteEvidenceStore,
    create_http_server,
)
from chp_core.cli import main as cli_main  # noqa: E402


class HTTPHostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("http-test-host", store=SQLiteEvidenceStore(":memory:"))

        async def add(_ctx, payload):
            return {"sum": payload["a"] + payload["b"]}

        self.host.register(
            CapabilityDescriptor(
                id="math.add",
                version="1.0.0",
                description="Add two numbers.",
            ),
            add,
        )
        self.server = create_http_server(self.host, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_discover_invoke_and_replay_over_http(self) -> None:
        host_descriptor = self.get("/host")
        self.assertEqual(host_descriptor["id"], "http-test-host")
        self.assertEqual(host_descriptor["capabilities"][0]["id"], "math.add")

        result = self.post(
            "/invoke",
            {
                "capability_id": "math.add",
                "payload": {"a": 4, "b": 5},
                "correlation_id": "corr-http",
            },
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["data"], {"sum": 9})
        self.assertEqual(result["correlation"]["correlation_id"], "corr-http")

        replay = self.get("/replay/corr-http")
        self.assertEqual(replay["event_count"], 2)
        self.assertEqual(
            [event["event_type"] for event in replay["events"]],
            ["execution_started", "execution_completed"],
        )

    def test_unknown_capability_returns_denial_result(self) -> None:
        result = self.post(
            "/invoke",
            {
                "capability_id": "missing.example",
                "payload": {},
                "correlation_id": "corr-missing-http",
            },
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "denied")
        self.assertEqual(result["denial"]["code"], "capability_not_found")

        replay = self.post(
            "/replay",
            {
                "correlation_id": "corr-missing-http",
                "include_payloads": False,
            },
        )
        self.assertEqual(replay["event_count"], 1)
        self.assertEqual(replay["events"][0]["event_type"], "execution_denied")
        self.assertEqual(replay["events"][0]["payload"], {})

    def test_cli_invokes_and_replays_served_host(self) -> None:
        invoke_output = StringIO()
        with redirect_stdout(invoke_output):
            exit_code = cli_main(
                [
                    "invoke",
                    "math.add",
                    "--url",
                    self.base_url,
                    "--payload",
                    '{"a":7,"b":8}',
                    "--correlation-id",
                    "corr-cli-http",
                ]
            )

        self.assertEqual(exit_code, 0)
        result = json.loads(invoke_output.getvalue())
        self.assertTrue(result["success"])
        self.assertEqual(result["data"], {"sum": 15})

        replay_output = StringIO()
        with redirect_stdout(replay_output):
            exit_code = cli_main(["replay", "corr-cli-http", "--url", self.base_url])

        self.assertEqual(exit_code, 0)
        replay = json.loads(replay_output.getvalue())
        self.assertEqual(replay["event_count"], 2)

    def get(self, path: str):
        with urlopen(f"{self.base_url}{path}", timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def post(self, path: str, body: dict):
        raw = json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


class RemoteCapabilityHostTests(unittest.TestCase):
    """Tests for RemoteCapabilityHost using a real threaded local server."""

    def setUp(self) -> None:
        self.local_host = LocalCapabilityHost("remote-test-host", store=SQLiteEvidenceStore(":memory:"))

        async def multiply(_ctx, payload):
            return {"product": payload["x"] * payload["y"]}

        self.local_host.register(
            CapabilityDescriptor(id="math.multiply", version="1.0.0", description="Multiply two numbers."),
            multiply,
        )
        self.server = create_http_server(self.local_host, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.remote = RemoteCapabilityHost(f"http://127.0.0.1:{self.server.server_port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_health_returns_ok(self) -> None:
        result = self.remote.health()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["host_id"], "remote-test-host")

    def test_discover_returns_capabilities(self) -> None:
        desc = self.remote.discover()
        cap_ids = [c["id"] for c in desc["capabilities"]]
        self.assertIn("math.multiply", cap_ids)

    def test_discover_with_filter(self) -> None:
        desc = self.remote.discover(id="math.multiply")
        self.assertEqual(len(desc["capabilities"]), 1)
        desc_none = self.remote.discover(id="no.such.cap")
        self.assertEqual(len(desc_none["capabilities"]), 0)

    def test_invoke_sync(self) -> None:
        result = self.remote.invoke("math.multiply", {"x": 3, "y": 7})
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"product": 21})

    def test_ainvoke_async(self) -> None:
        import asyncio
        result = asyncio.run(self.remote.ainvoke("math.multiply", {"x": 5, "y": 4}))
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"product": 20})

    def test_ainvoke_with_correlation(self) -> None:
        import asyncio
        result = asyncio.run(
            self.remote.ainvoke(
                "math.multiply",
                {"x": 2, "y": 2},
                correlation={"correlation_id": "remote-corr-001"},
            )
        )
        self.assertTrue(result.success)
        self.assertEqual(result.correlation.correlation_id, "remote-corr-001")

    def test_replay_returns_events(self) -> None:
        import asyncio
        asyncio.run(
            self.remote.ainvoke(
                "math.multiply",
                {"x": 1, "y": 1},
                correlation={"correlation_id": "remote-replay-001"},
            )
        )
        events = self.remote.replay("remote-replay-001")
        self.assertGreaterEqual(len(events), 2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("execution_started", event_types)
        self.assertIn("execution_completed", event_types)

    def test_replay_result_with_string(self) -> None:
        import asyncio
        asyncio.run(
            self.remote.ainvoke(
                "math.multiply",
                {"x": 6, "y": 6},
                correlation={"correlation_id": "remote-replay-002"},
            )
        )
        result = self.remote.replay_result("remote-replay-002")
        self.assertIn("events", result)
        self.assertGreaterEqual(result["event_count"], 2)

    def test_unknown_capability_returns_denied_result(self) -> None:
        result = self.remote.invoke("no.such.capability", {})
        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "denied")
        self.assertIsNotNone(result.denial)
        self.assertEqual(result.denial.code, "capability_not_found")  # type: ignore[union-attr]

    def test_result_has_invocation_id_and_capability_id(self) -> None:
        result = self.remote.invoke("math.multiply", {"x": 9, "y": 2})
        self.assertIn("inv", result.invocation_id)
        self.assertEqual(result.capability_id, "math.multiply")


if __name__ == "__main__":
    unittest.main()
