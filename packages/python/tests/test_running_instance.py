"""RunningInstance — running-instance identity for activated capabilities (M1.2).

Pins: identity (id) is STABLE across status transitions; a transition returns a NEW
immutable record (not a mutation); validation rejects bad strategy/status/empty ids;
and to_dict() conforms to schemas/running-instance.schema.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from chp_core import RunningInstance

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas" / "running-instance.schema.json").read_text()
)


def _instance(**over) -> RunningInstance:
    base = dict(
        capability_id="chp.example.json_transform",
        host_id="owned-host-1",
        binding_digest="sha256:deadbeef",
        strategy="DEPLOY",
    )
    base.update(over)
    return RunningInstance(**base)


def test_identity_stable_across_status_transition():
    inst = _instance(status="provisioning")
    running = inst.with_status("running")
    terminated = running.with_status("terminated")
    # same identity throughout
    assert inst.id == running.id == terminated.id
    assert inst.activated_at == running.activated_at
    # status actually changed, and the original is untouched (immutable)
    assert (inst.status, running.status, terminated.status) == (
        "provisioning", "running", "terminated")
    assert running.is_operational() and not terminated.is_operational()


def test_frozen_record_cannot_be_mutated():
    inst = _instance()
    with pytest.raises(Exception):
        inst.status = "running"  # type: ignore[misc]


@pytest.mark.parametrize("bad", [
    {"strategy": "TELEPORT"},
    {"status": "exploded"},
    {"capability_id": ""},
    {"host_id": ""},
    {"binding_digest": ""},
])
def test_validation_rejects_bad_fields(bad):
    with pytest.raises(ValueError):
        _instance(**bad)


def test_to_dict_conforms_to_schema():
    inst = _instance(status="running", plan_digest="sha256:plan", artifact={"ref": "oci://x@sha256:a"})
    Draft202012Validator(SCHEMA).validate(inst.to_dict())


def test_to_dict_omits_plan_digest_when_absent():
    assert "plan_digest" not in _instance().to_dict()
