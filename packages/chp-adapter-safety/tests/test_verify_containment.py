"""Tests for chp.adapters.safety.verify_containment — producer-independent OpenCell boundary check."""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_safety import SafetyAdapter
from chp_adapter_safety._containment import verify_cell_against_plan

_GOOD_OBS = {
    "guest_network_device": False, "non_root_user": True, "guest_credentials": [],
    "read_only_rootfs": True, "effect_channel": "/opencell", "channel_authenticated": True,
    "network_mode": "none", "runtime": "runsc",
}
_CONS = {"network": "none", "read_only": True, "docker_runtime": "runsc"}


def test_full_pass():
    ok, failures = verify_cell_against_plan(_GOOD_OBS, _CONS, boundary_class="gvisor-sandbox-kernel")
    assert ok and failures == []


@pytest.mark.parametrize("mutate,needle", [
    ({"guest_network_device": True}, "network device"),
    ({"non_root_user": False}, "non-root"),
    ({"guest_credentials": ["AWS_SECRET_ACCESS_KEY"]}, "credentials present"),
    ({"read_only_rootfs": False}, "read-only"),
    ({"channel_authenticated": False}, "effect channel not authenticated"),
    ({"network_mode": "bridge"}, "network_mode"),
    ({"runtime": "runc"}, "runtime"),
])
def test_each_failure_path(mutate, needle):
    obs = {**_GOOD_OBS, **mutate}
    ok, failures = verify_cell_against_plan(obs, _CONS, boundary_class="gvisor-sandbox-kernel")
    assert ok is False
    assert any(needle in f for f in failures), failures


def test_runtime_mismatch_is_boundary_downgrade():
    # a gVisor/microVM plan whose cell actually ran on plain runc must fail closed
    ok, failures = verify_cell_against_plan({**_GOOD_OBS, "runtime": "runc"},
                                            {**_CONS, "docker_runtime": "kata"}, boundary_class="microvm")
    assert ok is False and any("microvm" in f for f in failures)


def _host():
    h = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(h, SafetyAdapter())
    return h


def test_capability_pass_and_fail():
    host = _host()
    r = host.invoke("chp.adapters.safety.verify_containment",
                    {"observation": _GOOD_OBS, "constraints": _CONS, "boundary_class": "gvisor-sandbox-kernel"})
    assert r.outcome == "success" and r.data["satisfied"] is True

    r2 = host.invoke("chp.adapters.safety.verify_containment",
                     {"observation": {**_GOOD_OBS, "runtime": "runc"}, "constraints": _CONS})
    assert r2.outcome == "success" and r2.data["satisfied"] is False and r2.data["failures"]


def test_capability_rejects_non_object():
    r = _host().invoke("chp.adapters.safety.verify_containment",
                       {"observation": "x", "constraints": _CONS})
    assert r.outcome != "success"
