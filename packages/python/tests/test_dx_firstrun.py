"""First-run DX contract: guided bare CLI, friendly refused-connection errors,
demo.echo, and teaching capability_not_found denials."""

from __future__ import annotations

import asyncio
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import pytest

from chp_core.cli import main as cli_main
from chp_core.demo import build_demo_host


def test_bare_chp_prints_start_here_and_exits_zero():
    out = StringIO()
    with redirect_stdout(out):
        code = cli_main([])
    assert code == 0
    assert "start here" in out.getvalue()
    assert "chp hooks install" in out.getvalue()
    assert "chp serve-demo" in out.getvalue()


def test_connection_refused_is_friendly_not_a_traceback():
    err = StringIO()
    with redirect_stderr(err), pytest.raises(SystemExit) as exc:
        cli_main(["host", "--url", "http://127.0.0.1:9"])  # nothing listens on 9
    assert exc.value.code == 1
    msg = err.getvalue()
    assert "no CHP host responding" in msg
    assert "chp serve-demo" in msg
    assert "Traceback" not in msg


def test_demo_echo_is_registered_and_succeeds():
    host = build_demo_host()
    r = asyncio.run(host.ainvoke("demo.echo", {"text": "hi"}))
    assert r.success and r.data == {"echo": "hi"}


def test_capability_not_found_carries_suggestions():
    host = build_demo_host()
    r = asyncio.run(host.ainvoke("demo.ecoh", {}))
    assert r.outcome == "denied" and r.denial.code == "capability_not_found"
    assert "demo.echo" in r.denial.details["suggestions"]
    assert "capabilities" in r.denial.details["hint"]


def test_no_suggestions_for_gibberish():
    host = build_demo_host()
    r = asyncio.run(host.ainvoke("zzz.qqq.completely.unrelated", {}))
    assert r.outcome == "denied"
    assert r.denial.details["suggestions"] == []


# --- the default (dependency-free) install ------------------------------------
# chp-core declares no runtime dependencies, so jsonschema is absent for anyone who
# runs plain `pip install chp-core`. Every test above runs in a dev env where it IS
# installed, which is why a 500 on the advertised first-run shipped unnoticed.


@pytest.fixture
def without_jsonschema(monkeypatch):
    """Simulate the default install: jsonschema unimportable, cache cleared."""
    import builtins

    from chp_core import host as host_mod

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("No module named 'jsonschema'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(host_mod, "_JSONSCHEMA", host_mod._UNSET)
    monkeypatch.setattr(host_mod, "_SCHEMA_WARNED", False)
    yield
    monkeypatch.setattr(host_mod, "_JSONSCHEMA", host_mod._UNSET)


def test_schema_bearing_invocation_succeeds_without_jsonschema(without_jsonschema):
    """The regression: this raised UnboundLocalError and 500'd every such call."""
    host = build_demo_host()
    r = asyncio.run(host.ainvoke("demo.echo", {"text": "hi"}))
    assert r.success, f"schema-bearing invoke failed on a default install: {r.error}"
    assert r.data == {"echo": "hi"}


def test_missing_jsonschema_is_announced_not_silent(without_jsonschema):
    """Skipping a declared input_schema is a governance hole — it must be loud."""
    from chp_core.decorators import capability
    from chp_core.host import LocalCapabilityHost

    @capability(
        id="t.needs_schema",
        version="1.0.0",
        description="x",
        input_schema={"type": "object", "properties": {}},
    )
    def handler() -> dict:  # type: ignore[return-value]
        return {}

    with pytest.warns(RuntimeWarning, match="input_schema will NOT be enforced"):
        LocalCapabilityHost("t").register(handler)


def test_http_error_is_rendered_not_a_traceback():
    """A governance tool must never fail by traceback — the server's error, surfaced."""
    import json as _json
    from urllib.error import HTTPError

    from chp_core.cli import _core

    body = _json.dumps({"error": {"code": "bad_request", "message": "nope"}}).encode()

    def boom(*_a, **_k):
        raise HTTPError("http://h/invoke", 400, "Bad Request", {}, __import__("io").BytesIO(body))

    err = StringIO()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_core, "urlopen", boom)
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            _core.request_json("POST", "http://h/invoke", {})
    assert exc.value.code == 1
    assert "bad_request" in err.getvalue() and "nope" in err.getvalue()
    assert "Traceback" not in err.getvalue()
