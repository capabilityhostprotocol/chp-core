"""Trust-boundary robustness (proposal 0040): a hostile client sending valid JSON of
the wrong shape must get a clean 4xx — never a 500, a crash, or a hang — and the host
must survive it. Deserialization is where untrusted bytes become objects."""

from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.http import create_http_server
from chp_core.types import InvocationEnvelope

# Valid JSON, invalid CHP envelope shape — each must be a client error (4xx), not 500.
MALFORMED_BODIES = [
    "[1, 2, 3]",                                   # top-level array
    '"just a string"',                             # top-level string
    "42",                                          # top-level number
    "true",                                        # top-level bool
    "null",                                        # top-level null
    "{}",                                          # missing capability_id
    '{"payload": {}}',                             # missing capability_id
    '{"capability_id": 123}',                      # capability_id not a string
    '{"capability_id": null}',                     # capability_id null
    '{"capability_id": ""}',                       # capability_id empty
    '{"capability_id": ["x"]}',                    # capability_id an array
    '{"capability_id": "x", "payload": "str"}',    # payload not an object
    '{"capability_id": "x", "payload": 123}',      # payload a number
    '{"capability_id": "x", "payload": [1, 2]}',   # payload an array
    '{"capability_id": "x", "subject": "str"}',    # subject not an object
    '{"capability_id": "x", "metadata": 123}',     # metadata not an object
    '{"capability_id": "x", "correlation": "str"}',  # correlation not an object
    '{"capability_id": "x", "mandate": "str"}',    # mandate not an object
    '{"capability_id": "x", "correlation": {"baggage": "str"}}',  # nested wrong type
]


class WireRobustnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host = LocalCapabilityHost("fuzz-host", store=SQLiteEvidenceStore(":memory:"))

        async def echo(_c, p):
            return {"echo": p}

        self.host.register(CapabilityDescriptor(id="ok.cap", version="1.0.0", description="."), echo)
        self.server = create_http_server(self.host, bind="127.0.0.1", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def _post(self, raw_body: str):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/invoke", raw_body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp.status, body

    # Structurally-broken bodies that MUST be rejected as a 400 (the shape is
    # unrecoverable — not a field we choose to coerce like an optional baggage).
    _MUST_400 = {
        "[1, 2, 3]", '"just a string"', "42", "true", "null", "{}", '{"payload": {}}',
        '{"capability_id": 123}', '{"capability_id": null}', '{"capability_id": ""}',
        '{"capability_id": ["x"]}', '{"capability_id": "x", "payload": "str"}',
        '{"capability_id": "x", "payload": 123}', '{"capability_id": "x", "payload": [1, 2]}',
        '{"capability_id": "x", "subject": "str"}', '{"capability_id": "x", "metadata": 123}',
        '{"capability_id": "x", "correlation": "str"}', '{"capability_id": "x", "mandate": "str"}',
    }

    def test_malformed_bodies_never_500(self) -> None:
        """The load-bearing guarantee: no malformed body causes a 500/crash/hang."""
        for raw in MALFORMED_BODIES:
            with self.subTest(body=raw):
                status, body = self._post(raw)
                self.assertLess(status, 500,
                                f"malformed body must not 500: {raw!r} → {status} {body}")
                if raw in self._MUST_400:
                    self.assertEqual(status, 400,
                                     f"structurally-broken body must be a 400: {raw!r} → {status}")

    def test_host_survives_the_fuzz_and_still_serves(self) -> None:
        for raw in MALFORMED_BODIES:
            self._post(raw)
        # after the whole malformed barrage, a well-formed request still succeeds
        status, body = self._post(json.dumps(
            {"capability_id": "ok.cap", "payload": {"v": 1}, "correlation_id": "after"}))
        self.assertEqual(status, 200, f"host must survive the fuzz: {status} {body}")
        self.assertTrue(json.loads(body)["success"])

    def test_from_mapping_rejects_cleanly_not_typeerror(self) -> None:
        # unit-level: the deserializer raises ValueError (→ 400), never TypeError (→ 500)
        for bad in [{"capability_id": 1}, {"capability_id": "x", "payload": "s"},
                    {"capability_id": "x", "mandate": "s"}, "not-a-dict"]:
            with self.assertRaises(ValueError):
                InvocationEnvelope.from_mapping(bad)


if __name__ == "__main__":
    unittest.main()
