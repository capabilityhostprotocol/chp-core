"""AdmissionDecision emission wiring (proposal 0043, CHP-CORE-029).

The live pipeline reifies the admission decision onto execution_started: bound to the exact
invocation_digest, with REAL four-state invariant results — a passing host invariant reads
satisfied, and a warn-behavior invariant that fails is recorded unsatisfied while the
invocation is still admitted (honest four-state, not a blanket 'satisfied').
"""

import asyncio

from chp_core import (
    CapabilityDescriptor,
    CorrelationContext,
    InvariantDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)


async def _handler(_ctx, _payload):
    return {"ok": True}


def _host(invariant: InvariantDescriptor) -> LocalCapabilityHost:
    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    host.register(
        CapabilityDescriptor(id="svc.do", version="1.0.0", description="x", invariants=[invariant]),
        _handler,
    )
    return host


def _invoke(host: LocalCapabilityHost, payload: dict) -> list[dict]:
    asyncio.run(host.ainvoke("svc.do", payload, correlation=CorrelationContext(correlation_id="c")))
    return host.replay("c")


def test_execution_started_carries_admission_bound_to_digest():
    host = _host(InvariantDescriptor(
        id="needs.target", kind="required_payload_fields", enforcement="host",
        failure_behavior="deny", parameters={"fields": ["target"]},
    ))
    events = _invoke(host, {"target": "db"})
    started = next(e for e in events if e["event_type"] == "execution_started")
    completed = next(e for e in events if e["event_type"] == "execution_completed")

    adm = started["admission"]
    assert adm["result"] == "admitted"
    assert adm["invocation_digest"].startswith("sha256:")
    assert {"id": "needs.target", "status": "satisfied"} in adm["invariant_evaluations"]
    assert adm["invocation_digest"] == completed["invocation_digest"]  # same governed attempt
    assert "admission" not in completed  # attached only to execution_started


def test_admission_records_failing_warn_invariant_unsatisfied_and_still_admits():
    # A warn-behavior invariant that fails must NOT deny, but must be recorded unsatisfied —
    # unknown/unsatisfied is never laundered into 'satisfied' (CHP-CORE-017 spirit).
    host = _host(InvariantDescriptor(
        id="prefers.note", kind="required_payload_fields", enforcement="host",
        failure_behavior="warn", parameters={"fields": ["note"]},
    ))
    events = _invoke(host, {"target": "db"})  # 'note' missing → invariant violated
    assert any(e["event_type"] == "execution_completed" for e in events)  # still admitted
    adm = next(e for e in events if e["event_type"] == "execution_started")["admission"]
    assert adm["result"] == "admitted"
    assert {"id": "prefers.note", "status": "unsatisfied"} in adm["invariant_evaluations"]
