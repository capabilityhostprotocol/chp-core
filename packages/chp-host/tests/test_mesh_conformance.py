"""Self-test: the REFERENCE gateway passes the mesh conformance suite.

Runs conformance/runner.py's mesh suite end-to-end: the runner hosts two
member hosts, this test launches `chp-host gateway` as a real subprocess
pointed at them (via a generated keyless manifest with a tmp evidence store),
and the 8 routing-intermediary checks (spec §11 + §10 Forwarding) must pass.
This is the continuous proof that the reference implementation satisfies the
obligations MESH-FIXTURES.md asks of any implementation.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "conformance"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_reference_gateway_passes_mesh_suite(tmp_path):
    # All waits inside run_mesh are poll-with-timeout (45s gateway budget),
    # so the test is self-bounding without pytest-timeout.
    from runner import run_mesh

    member_ports = (_free_port(), _free_port())
    gateway_port = _free_port()
    gateway_url = f"http://127.0.0.1:{gateway_port}"
    proc_holder: dict = {}

    def launch_gateway(member_urls: dict) -> None:
        manifest = {
            "name": "mesh-selftest",
            "agent_remotes": [{"url": url} for url in member_urls.values()],
            "gateway": {
                "port": gateway_port,
                "bind": "127.0.0.1",
                "host_id": "mesh-selftest-gateway",
                # NEVER the default ~/.chp/gateway-mesh.sqlite — tmp only.
                "store": str(tmp_path / "gateway.sqlite"),
            },
        }
        manifest_path = tmp_path / "mesh-selftest.json"
        manifest_path.write_text(json.dumps(manifest))
        proc_holder["proc"] = subprocess.Popen(
            [sys.executable, "-m", "chp_host.cli", "gateway",
             "--environment", str(manifest_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    try:
        results = asyncio.run(run_mesh(
            gateway_url, member_ports=member_ports,
            after_members=launch_gateway, gateway_timeout=45.0))
    finally:
        proc = proc_holder.get("proc")
        if proc:
            proc.terminate()
            try:
                out = proc.communicate(timeout=10)[0]
            except subprocess.TimeoutExpired:
                proc.kill()
                out = proc.communicate()[0]
        else:
            out = "<gateway never launched>"

    failures = [(r.name, r.detail) for r in results if not r.ok]
    assert not failures, (
        f"mesh suite failures: {failures}\n--- gateway output ---\n{out[-3000:]}")
    assert len(results) == 8


def test_mesh_suite_requires_gateway_url(capsys):
    """`--suite mesh` without --gateway-url exits with guidance, not a stack."""
    from runner import main

    argv = sys.argv
    sys.argv = ["runner.py", "--suite", "mesh"]
    try:
        assert main() == 2
    finally:
        sys.argv = argv
