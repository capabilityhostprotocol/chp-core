"""Production serve-path resilience (hardening arc): catch-all 500 with an
operator signal, the SIGTERM drain, and the REQUIRE_AUTH posture flag."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.http import create_http_server


def _serve(host):
    server = create_http_server(host, bind="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class CatchAllTests(unittest.TestCase):
    def test_unhandled_exception_is_structured_500_and_counted(self) -> None:
        host = LocalCapabilityHost("resilience-host", store=SQLiteEvidenceStore(":memory:"))
        # Force an exception past the processed-result path: replay_result
        # raising inside do_GET is not caught by the typed except arms.
        host.replay_result = unittest.mock.Mock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        server, base = _serve(host)
        try:
            from chp_core import metrics
            before = metrics._INTERNAL_ERRORS["count"]
            with self.assertRaises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(f"{base}/replay/x", timeout=10)
            self.assertEqual(exc.exception.code, 500)
            body = json.loads(exc.exception.read())
            self.assertEqual(body["error"]["code"], "internal_error")
            self.assertEqual(metrics._INTERNAL_ERRORS["count"], before + 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_metrics_exposes_the_counter(self) -> None:
        host = LocalCapabilityHost("metrics-host", store=SQLiteEvidenceStore(":memory:"))
        server, base = _serve(host)
        try:
            text = urllib.request.urlopen(f"{base}/metrics", timeout=10).read().decode()
            self.assertIn("chp_http_internal_errors_total", text)
            self.assertIn("chp_store_size_bytes", text)
            self.assertIn("chp_store_events_total", text)
        finally:
            server.shutdown()
            server.server_close()


class RequireAuthTests(unittest.TestCase):
    def test_refuses_to_start_keyless_when_required(self) -> None:
        host = LocalCapabilityHost("auth-host", store=SQLiteEvidenceStore(":memory:"))
        env = {"CHP_HOST_REQUIRE_AUTH": "1"}
        for k in ("CHP_HOST_API_KEYS", "CHP_HOST_API_KEY"):
            env[k] = ""
        with unittest.mock.patch.dict(os.environ, env):
            os.environ.pop("CHP_HOST_API_KEYS", None)
            os.environ.pop("CHP_HOST_API_KEY", None)
            with self.assertRaises(RuntimeError):
                create_http_server(host, bind="127.0.0.1", port=0)

    def test_starts_with_a_key_when_required(self) -> None:
        host = LocalCapabilityHost("auth-host-2", store=SQLiteEvidenceStore(":memory:"))
        with unittest.mock.patch.dict(
                os.environ, {"CHP_HOST_REQUIRE_AUTH": "1", "CHP_HOST_API_KEY": "k"}):
            server = create_http_server(host, bind="127.0.0.1", port=0)
            server.server_close()


_DRAIN_CHILD = textwrap.dedent("""
    import sys, threading, time, urllib.request, json
    sys.path.insert(0, sys.argv[1])
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.http import create_http_server, install_sigterm_drain

    host = LocalCapabilityHost("drain-host", store=SQLiteEvidenceStore(":memory:"))

    async def slow(_ctx, payload):
        time.sleep(float(payload.get("sleep_s", 2)))
        return {"done": True}

    host.register(CapabilityDescriptor(id="drain.slow", version="1.0.0",
                                       description="Sleep then return."), slow)
    server = create_http_server(host, bind="127.0.0.1", port=0)
    assert install_sigterm_drain()
    print(server.server_address[1], flush=True)
    server.serve_forever()
""")


class SigtermDrainTests(unittest.TestCase):
    def test_sigterm_waits_for_inflight_then_exits_zero(self) -> None:
        pkg_dir = str(Path(__file__).resolve().parents[1])
        proc = subprocess.Popen(
            [sys.executable, "-c", _DRAIN_CHILD, pkg_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert proc.stdout is not None
            port = int(proc.stdout.readline().strip())
            base = f"http://127.0.0.1:{port}"

            result: dict = {}

            def invoke() -> None:
                req = urllib.request.Request(
                    f"{base}/invoke",
                    data=json.dumps({"capability_id": "drain.slow",
                                     "payload": {"sleep_s": 2}}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result.update(json.loads(resp.read()))

            t = threading.Thread(target=invoke)
            t.start()
            import time as _time
            _time.sleep(0.5)  # the invoke is in flight
            proc.send_signal(signal.SIGTERM)
            t.join(timeout=20)

            # The in-flight invocation completed despite the SIGTERM...
            self.assertEqual(result.get("outcome"), "success",
                             f"in-flight invoke was dropped: {result}")
            # ...and the process exited cleanly within the drain window.
            self.assertEqual(proc.wait(timeout=20), 0)
        finally:
            proc.kill()


if __name__ == "__main__":
    unittest.main()
