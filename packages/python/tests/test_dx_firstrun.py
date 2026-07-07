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
    assert "start here:" in out.getvalue()
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
