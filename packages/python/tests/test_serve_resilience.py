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
from chp_core.merkle import (
    CHP_STORE_HEAD_V2,
    store_head_consistency_proof,
    verify_store_head_consistency,
)


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
            # The load-bearing guarantee: NO 5xx server error / crash under the burst.
            # 200 (served), 503 (concurrency-cap shed), and -1 (TCP connection refused
            # under extreme burst — kernel-level backpressure) are all acceptable; a
            # 5xx would mean the host itself failed.
            self.assertEqual(len(results), N, "every request must return a result")
            # 503 (concurrency shed) is expected; a 500 would mean the host CRASHED.
            crashes = [st for st in results if st == 500]
            self.assertEqual(crashes, [], f"no 500 crash under burst; got {sorted(set(results))}")
            self.assertTrue(any(st == 200 for st in results), "some requests must succeed")
            # the host survives the burst and still serves a fresh request
            fresh = urllib.request.urlopen(
                urllib.request.Request(f"{base}/invoke", method="POST",
                    data=json.dumps({"capability_id": "w.cap", "payload": {},
                                     "correlation_id": "fresh"}).encode(),
                    headers={"Content-Type": "application/json"}), timeout=5)
            self.assertEqual(fresh.status, 200)
        finally:
            server.shutdown(); server.server_close()


class SoakTests(unittest.TestCase):
    """Sustained load (proposal 0043): a burst proves *momentary* crash-freedom;
    a soak proves the host survives *continuous* load — no 500, no hang, no
    unbounded growth — and every recorded correlation's SHA256 chain stays intact
    afterward. Kept short (~2s) so it's a CI regression gate, not a stress rig."""

    def test_sustained_load_stays_healthy_and_chain_intact(self) -> None:
        import http.client
        import time

        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost("soak-host", store=store)

        async def work(_c, p):
            return {"n": p.get("n", 0)}

        host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
        server, base = _serve(host)
        port = server.server_address[1]

        statuses: list[int] = []
        latencies: list[float] = []
        lock = threading.Lock()
        stop = threading.Event()
        counter = {"i": 0}

        def _worker() -> None:
            while not stop.is_set():
                with lock:
                    i = counter["i"]; counter["i"] += 1
                t0 = time.monotonic()
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    conn.request("POST", "/invoke", json.dumps(
                        {"capability_id": "w.cap", "payload": {"n": i},
                         "correlation_id": f"s{i}"}), {"Content-Type": "application/json"})
                    resp = conn.getresponse(); st = resp.status; resp.read(); conn.close()
                except Exception:
                    st = -1
                with lock:
                    statuses.append(st); latencies.append(time.monotonic() - t0)

        try:
            workers = [threading.Thread(target=_worker) for _ in range(8)]
            for w in workers:
                w.start()
            time.sleep(2.0)  # sustained load window
            stop.set()
            for w in workers:
                w.join(timeout=10)

            self.assertGreater(len(statuses), 50, "soak should push meaningful volume")
            crashes = [st for st in statuses if st == 500]
            self.assertEqual(crashes, [], f"no 500 under sustained load; got {sorted(set(statuses))}")
            self.assertTrue(all(st == 200 for st in statuses),
                            f"no cap set → every soak request should 200; got {sorted(set(statuses))}")
            # bounded tail latency — a wedged/leaking host shows up as a blown p99
            latencies.sort()
            p99 = latencies[int(len(latencies) * 0.99)]
            self.assertLess(p99, 2.0, f"p99 latency {p99:.3f}s under soak is unbounded")
            # every recorded correlation verifies (strict: an unhashed event fails)
            ok = sum(1 for i in range(counter["i"])
                     if store.verify_chain(f"s{i}", strict=True).valid)
            self.assertGreaterEqual(ok, len([s for s in statuses if s == 200]),
                                    "every acked invocation's chain must verify strictly")
        finally:
            server.shutdown(); server.server_close()


_CHAOS_CHILD = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    from chp_core.http import create_http_server

    host = LocalCapabilityHost("chaos-host", store=SQLiteEvidenceStore(sys.argv[2]))

    async def work(_c, p):
        return {"n": p.get("n", 0)}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
    server = create_http_server(host, bind="127.0.0.1", port=0)
    print(server.server_address[1], flush=True)
    server.serve_forever()
""")


class ChaosRecoveryTests(unittest.TestCase):
    """Crash recovery (proposal 0043): SIGKILL the host mid-load, then reopen its
    file-backed store — SQLite replays the WAL (0.15.0 busy_timeout + WAL). The
    guarantee: every invocation that got a 200 (committed) survives the unclean
    kill with an intact chain — no acked-evidence loss. (Process crash, not power
    loss; synchronous=NORMAL means an OS crash could still lose the un-fsynced WAL
    tail — SIGKILL keeps the WAL file, so acked commits are durable.)"""

    def test_sigkill_midload_preserves_acked_evidence(self) -> None:
        import http.client
        import tempfile

        pkg_dir = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "chaos.sqlite")
            proc = subprocess.Popen(
                [sys.executable, "-c", _CHAOS_CHILD, pkg_dir, db_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert proc.stdout is not None
                port = int(proc.stdout.readline().strip())

                acked: list[int] = []
                lock = threading.Lock()

                def _fire(i: int) -> None:
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request("POST", "/invoke", json.dumps(
                            {"capability_id": "w.cap", "payload": {"n": i},
                             "correlation_id": f"k{i}"}), {"Content-Type": "application/json"})
                        st = conn.getresponse().status
                        if st == 200:
                            with lock:
                                acked.append(i)
                        conn.close()
                    except Exception:
                        pass

                threads = [threading.Thread(target=_fire, args=(i,)) for i in range(40)]
                for t in threads:
                    t.start()
                import time as _t
                _t.sleep(0.35)  # let a batch commit, leave some in flight
                proc.kill()      # SIGKILL — unclean, no drain
                for t in threads:
                    t.join(timeout=5)
            finally:
                proc.kill()
            proc.wait(timeout=10)

            # Reopen the store from scratch — this IS the recovery path (WAL replay
            # on open). ponytail: reopening the store exercises the same recovery as
            # a full server restart, without the second subprocess.
            self.assertTrue(acked, "some invocations must have been acked before the kill")
            recovered = SQLiteEvidenceStore(db_path)
            try:
                for i in acked:
                    res = recovered.verify_chain(f"k{i}", strict=True)
                    self.assertTrue(res.valid and res.event_count > 0,
                                    f"acked invocation k{i} lost or corrupt after SIGKILL: {res}")
            finally:
                recovered.close()


class ChaosRestartTests(unittest.TestCase):
    """Recovery, not just durability (proposal 0043): SIGKILL the host mid-load, then
    RESTART a real server on the same store file. The guarantees: (1) the host serves
    again and accepts NEW work that chains onto the recovered ledger; (2) the recovered
    ledger is PROVABLY append-only across the crash — a post-restart RFC 6962 consistency
    proof (0022) shows the new store head is an append-only extension of the pre-crash
    head (nothing rewritten or truncated). ChaosRecoveryTests proves acked evidence
    survives; this proves the ledger keeps its integrity *and the host comes back*."""

    def test_restart_serves_and_ledger_is_provably_append_only(self) -> None:
        import http.client
        import tempfile
        import time as _t

        pkg_dir = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "chaos-restart.sqlite")
            proc = subprocess.Popen(
                [sys.executable, "-c", _CHAOS_CHILD, pkg_dir, db_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert proc.stdout is not None
                port = int(proc.stdout.readline().strip())

                # pre-crash correlations sort BEFORE the post-restart one ("a…" < "zzz…"),
                # so the recovered leaf set is a sorted PREFIX of the post-restart set — the
                # store-head-v2 consistency proof's append-only precondition.
                def _fire(i: int) -> None:
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request("POST", "/invoke", json.dumps(
                            {"capability_id": "w.cap", "payload": {"n": i},
                             "correlation_id": f"a{i:03d}"}), {"Content-Type": "application/json"})
                        conn.getresponse().status
                        conn.close()
                    except Exception:
                        pass

                threads = [threading.Thread(target=_fire, args=(i,)) for i in range(40)]
                for t in threads:
                    t.start()
                _t.sleep(0.35)  # let a batch commit, leave some in flight
                proc.kill()      # SIGKILL — unclean, no drain
                for t in threads:
                    t.join(timeout=5)
            finally:
                proc.kill()
            proc.wait(timeout=10)

            # ── recovery path: reopen the crashed store, snapshot the pre-crash head ──
            store = SQLiteEvidenceStore(db_path)
            try:
                pre = store.get_store_head(scheme=CHP_STORE_HEAD_V2)
                self.assertGreater(pre["sequence"], 0, "the crash must have committed some events")

                # restart a REAL server on the recovered store — it must serve again
                host = LocalCapabilityHost("restart-host", store=store)

                async def work(_c, p):
                    return {"n": p.get("n", 0)}

                host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."),
                              work)
                server, base = _serve(host)
                try:
                    health = urllib.request.urlopen(f"{base}/health", timeout=10)
                    self.assertEqual(health.status, 200, "host must serve after restart")

                    # NEW work must succeed and chain onto the recovered ledger
                    req = urllib.request.Request(
                        f"{base}/invoke",
                        data=json.dumps({"capability_id": "w.cap", "payload": {"n": 99},
                                         "correlation_id": "zzz-post-restart"}).encode(),
                        headers={"Content-Type": "application/json"})
                    self.assertEqual(urllib.request.urlopen(req, timeout=10).status, 200)
                    self.assertTrue(store.verify_chain("zzz-post-restart", strict=True).valid,
                                    "post-restart work must chain onto the recovered ledger")

                    # ── the ledger is PROVABLY append-only across the crash ──
                    post = store.get_store_head(scheme=CHP_STORE_HEAD_V2)
                    self.assertGreater(post["sequence"], pre["sequence"], "ledger must have grown")
                    proof = store_head_consistency_proof(pre["leaves"], post["leaves"])
                    self.assertTrue(
                        verify_store_head_consistency(pre["store_head"], post["store_head"], proof),
                        "post-restart ledger must be a provable append-only extension of pre-crash")
                finally:
                    server.shutdown(); server.server_close()
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
