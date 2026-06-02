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


if __name__ == "__main__":
    unittest.main()
