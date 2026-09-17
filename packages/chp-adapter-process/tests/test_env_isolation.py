"""inherit_env=False builds the child env from an allowlist only, so an untrusted
candidate cannot read harness secrets that live in os.environ. (rad:f9adc17)"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import uuid

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.host import _stringify_floats
from chp_core.signing import build_approval_grant, generate_keypair
from chp_core.store import SQLiteEvidenceStore, _payload_commitment
from chp_core.types import InvocationEnvelope

from chp_adapter_process import ProcessAdapter, ProcessConfig

_APPROVER = generate_keypair(tempfile.mkdtemp())
_PYTHON = sys.executable
CANARY = "AUXO_HARNESS_CANARY"
_PROBE = f"import os; print(os.environ.get({CANARY!r}, '<absent>'))"


def _make_host(config=None):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, ProcessAdapter(config))
    return host


def _run(host, payload):
    inv = "inv-" + uuid.uuid4().hex[:12]
    grant = build_approval_grant(
        _APPROVER, invocation_id=inv, approval_id="ap-" + inv,
        payload_commitment=_payload_commitment(_stringify_floats(payload)),
        valid_until="2099-01-01T00:00:00Z")
    env = InvocationEnvelope(capability_id="chp.adapters.process.run", invocation_id=inv,
                             payload=payload, approval_ref=grant)
    return asyncio.run(host.ainvoke_envelope(env))


def test_candidate_cannot_see_harness_secret_when_not_inheriting(monkeypatch):
    monkeypatch.setenv(CANARY, "TOP-SECRET-should-not-leak")
    host = _make_host(ProcessConfig(inherit_env=False))
    r = _run(host, {"command": _PYTHON, "args": ["-c", _PROBE]})
    assert r.outcome == "success"
    assert "<absent>" in r.data["stdout"]           # canary NOT visible to the child
    assert "TOP-SECRET" not in r.data["stdout"]


def test_default_inherits_env_backward_compatible(monkeypatch):
    monkeypatch.setenv(CANARY, "visible-by-default")
    host = _make_host()  # default inherit_env=True
    r = _run(host, {"command": _PYTHON, "args": ["-c", _PROBE]})
    assert r.outcome == "success"
    assert "visible-by-default" in r.data["stdout"]  # prior behavior unchanged


def test_env_passthrough_allowlist_and_additions(monkeypatch):
    monkeypatch.setenv(CANARY, "nope")
    monkeypatch.setenv("AUXO_ALLOWED_VAR", "yes-allowed")
    host = _make_host(ProcessConfig(inherit_env=False, env_passthrough=["AUXO_ALLOWED_VAR"]))
    probe = ("import os;"
             f"print(os.environ.get({CANARY!r}, '<absent>'),"
             "os.environ.get('AUXO_ALLOWED_VAR', '<absent>'),"
             "os.environ.get('AUXO_EXTRA', '<absent>'))")
    r = _run(host, {"command": _PYTHON, "args": ["-c", probe],
                    "env_additions": {"AUXO_EXTRA": "from-additions"}})
    assert r.outcome == "success"
    out = r.data["stdout"]
    assert "<absent>" in out                # canary excluded
    assert "yes-allowed" in out             # allowlisted name crosses
    assert "from-additions" in out          # env_additions still applied


def test_payload_overrides_config_inherit_env(monkeypatch):
    monkeypatch.setenv(CANARY, "leak-me")
    host = _make_host()  # config default inherit_env=True
    r = _run(host, {"command": _PYTHON, "args": ["-c", _PROBE], "inherit_env": False})
    assert r.outcome == "success"
    assert "<absent>" in r.data["stdout"]   # per-call override wins
