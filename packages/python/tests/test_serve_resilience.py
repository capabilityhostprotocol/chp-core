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


class ConcurrencyLimitTests(unittest.TestCase):
    """Production hardening (proposal 0039): a bounded concurrency cap sheds excess
    load with a fast 503 instead of spawning unbounded threads."""

    def test_over_cap_sheds_503_and_recovers(self) -> None:
        import http.client

        started = threading.Event()
        release = threading.Event()

        async def slow(_ctx, _payload):
            started.set()
            release.wait(timeout=10)  # hold the one concurrency slot
            return {"ok": True}

        host = LocalCapabilityHost("cap-host", store=SQLiteEvidenceStore(":memory:"))
        host.register(CapabilityDescriptor(id="slow.cap", version="1.0.0", description="."), slow)

        prev = os.environ.get("CHP_HOST_MAX_CONCURRENCY")
        os.environ["CHP_HOST_MAX_CONCURRENCY"] = "1"  # read at create_http_server time
        try:
            server, base = _serve(host)
        finally:
            if prev is None:
                os.environ.pop("CHP_HOST_MAX_CONCURRENCY", None)
            else:
                os.environ["CHP_HOST_MAX_CONCURRENCY"] = prev

        port = server.server_address[1]

        def _post(path, body, timeout=10):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
            conn.request("POST", path, json.dumps(body),
                         {"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read().decode()
            conn.close()
            return resp.status, data

        try:
            # Request A fills the single slot and blocks inside the handler.
            a_result: list = []
            a = threading.Thread(target=lambda: a_result.append(
                _post("/invoke", {"capability_id": "slow.cap", "payload": {},
                                  "correlation_id": "a"})), daemon=True)
            a.start()
            self.assertTrue(started.wait(timeout=5), "request A must reach the handler")

            # Request B arrives at capacity → a fast 503 with the shed code.
            st, body = _post("/invoke", {"capability_id": "slow.cap", "payload": {},
                                         "correlation_id": "b"}, timeout=5)
            self.assertEqual(st, 503, f"over-cap request must be shed with 503, got {st}")
            self.assertEqual(json.loads(body)["error"]["code"], "server_at_capacity")

            # Release A; the slot frees and a later request succeeds.
            release.set()
            a.join(timeout=5)
            self.assertEqual(a_result[0][0], 200, "request A must complete once released")
            st2, _ = _post("/invoke", {"capability_id": "slow.cap", "payload": {},
                                       "correlation_id": "c"}, timeout=5)
            self.assertEqual(st2, 200, "a request after the slot frees must succeed")
        finally:
            release.set()
            server.shutdown(); server.server_close()

    def test_cap_disabled_when_zero(self) -> None:
        prev = os.environ.get("CHP_HOST_MAX_CONCURRENCY")
        os.environ["CHP_HOST_MAX_CONCURRENCY"] = "0"
        try:
            host = LocalCapabilityHost("nocap", store=SQLiteEvidenceStore(":memory:"))
            server = create_http_server(host, bind="127.0.0.1", port=0)
            self.assertIsNone(server._concurrency, "cap=0 disables the semaphore")
            server.server_close()
        finally:
            if prev is None:
                os.environ.pop("CHP_HOST_MAX_CONCURRENCY", None)
            else:
                os.environ["CHP_HOST_MAX_CONCURRENCY"] = prev


class RateLimitTests(unittest.TestCase):
    """Per-caller rate limiting (proposal 0041): a token bucket keyed on the caller
    returns 429 over the limit, and the shed/limit counters are observable."""

    def _serve_with_env(self, host, **env):
        prev = {k: os.environ.get(k) for k in env}
        os.environ.update({k: str(v) for k, v in env.items()})
        try:
            return _serve(host)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_over_limit_is_429_and_counted_and_recovers(self) -> None:
        import http.client

        host = LocalCapabilityHost("rl-host", store=SQLiteEvidenceStore(":memory:"))

        async def echo(_c, p):
            return {"ok": True}

        host.register(CapabilityDescriptor(id="ok.cap", version="1.0.0", description="."), echo)
        # 3 requests / 60s window → refill is negligible during the test (deterministic).
        server, base = self._serve_with_env(host, CHP_HOST_RATE_LIMIT=3, CHP_HOST_RATE_WINDOW_S=60)
        port = server.server_address[1]

        def _post():
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/invoke", json.dumps(
                {"capability_id": "ok.cap", "payload": {}, "correlation_id": "x"}),
                {"Content-Type": "application/json"})
            r = conn.getresponse(); body = r.read().decode(); conn.close()
            return r.status, body

        try:
            statuses = [_post()[0] for _ in range(4)]  # same caller (127.0.0.1)
            self.assertEqual(statuses[:3], [200, 200, 200], f"first 3 within limit: {statuses}")
            self.assertEqual(statuses[3], 429, f"4th over the limit must be 429: {statuses}")
            last = _post()
            self.assertEqual(last[0], 429)
            self.assertEqual(json.loads(last[1])["error"]["code"], "rate_limited")
            # the rejection is observable on /metrics
            m = urllib.request.urlopen(f"{base}/metrics", timeout=5).read().decode()
            self.assertRegex(m, r"chp_http_rate_limited_total [1-9]")
        finally:
            server.shutdown(); server.server_close()


class LoadBurstTests(unittest.TestCase):
    """Load harness (proposal 0041): a burst far exceeding the concurrency cap is
    answered entirely with 200/503 — never a 500 or a hang — and the host survives."""

    def test_burst_beyond_cap_stays_healthy(self) -> None:
        import http.client

        host = LocalCapabilityHost("burst-host", store=SQLiteEvidenceStore(":memory:"))

        async def work(_c, p):
            return {"n": p.get("n", 0)}

        host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
        prev = os.environ.get("CHP_HOST_MAX_CONCURRENCY")
        os.environ["CHP_HOST_MAX_CONCURRENCY"] = "5"
        try:
            server, base = _serve(host)
        finally:
            if prev is None:
                os.environ.pop("CHP_HOST_MAX_CONCURRENCY", None)
            else:
                os.environ["CHP_HOST_MAX_CONCURRENCY"] = prev
        port = server.server_address[1]

        results: list[int] = []
        lock = threading.Lock()

        def _fire(i: int) -> None:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("POST", "/invoke", json.dumps(
                    {"capability_id": "w.cap", "payload": {"n": i}, "correlation_id": f"b{i}"}),
                    {"Content-Type": "application/json"})
                resp = conn.getresponse()
                st = resp.status
                resp.read()
                conn.close()
            except Exception:
                st = -1
            with lock:
                results.append(st)

        try:
            N = 60  # 12× the cap
            threads = [threading.Thread(target=_fire, args=(i,)) for i in range(N)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
            # every request got a definitive answer; none was a 500 or a dropped conn
            self.assertEqual(len(results), N, "every request must return")
            self.assertTrue(all(st in (200, 503) for st in results),
                            f"burst answered only with 200/503, got {sorted(set(results))}")
            self.assertNotIn(-1, results, "no dropped connections")
            # the host survives the burst and still serves a fresh request
            fresh = urllib.request.urlopen(
                urllib.request.Request(f"{base}/invoke", method="POST",
                    data=json.dumps({"capability_id": "w.cap", "payload": {},
                                     "correlation_id": "fresh"}).encode(),
                    headers={"Content-Type": "application/json"}), timeout=5)
            self.assertEqual(fresh.status, 200)
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
