"""execution_id + indeterminate outcome (proposal 0043, CHP-CORE-012/014/015).

Proves indeterminate is a distinct outcome (not success, not failure), execution_id is
distinct from invocation_id, a later reconciliation ADDS a record without rewriting the
earlier indeterminate state, and pre-0043 events omit the new fields byte-identically.
"""

import json
import typing
from pathlib import Path

import jsonschema

from chp_core import CorrelationContext, ExecutionOutcome
from chp_core.types import ExecutionEvidence

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/evidence-event.schema.json").read_text()
)


def _evt(**kw) -> ExecutionEvidence:
    base = dict(
        event_id="evt-1",
        event_type="execution_completed",
        invocation_id="inv-1",
        capability_id="svc.do",
        capability_version="1.0.0",
        host_id="host-A",
        correlation=CorrelationContext(correlation_id="c"),
    )
    base.update(kw)
    return ExecutionEvidence(**base)


def test_indeterminate_is_a_distinct_outcome():
    assert "indeterminate" in typing.get_args(ExecutionOutcome)
    assert "indeterminate" not in ("success", "failure")  # never collapsed into either
    # validate just the outcome subschema (avoids external $ref resolution)
    jsonschema.validate("indeterminate", _SCHEMA["properties"]["outcome"])


def test_execution_id_distinct_from_invocation_id():
    d = _evt(execution_id="exec-1", outcome="indeterminate").to_dict()
    assert d["execution_id"] == "exec-1"
    assert d["invocation_id"] == "inv-1"
    assert d["execution_id"] != d["invocation_id"]  # CHP-CORE-012
    assert d["outcome"] == "indeterminate"
    jsonschema.validate("exec-1", _SCHEMA["properties"]["execution_id"])


def test_reconciliation_adds_record_without_rewriting_indeterminate():
    # CHP-CORE-015: a later reconciliation is a NEW record; the earlier indeterminate one
    # is immutable and preserved.
    first = _evt(event_id="evt-1", execution_id="exec-1", outcome="indeterminate", sequence=1)
    reconciled = _evt(event_id="evt-2", execution_id="exec-1", outcome="success", sequence=2)
    assert first.to_dict()["outcome"] == "indeterminate"  # unchanged by the later record
    assert reconciled.to_dict()["outcome"] == "success"
    assert first.execution_id == reconciled.execution_id  # same execution, two records


def test_pre_0043_event_omits_new_fields():
    d = _evt(outcome="success").to_dict()  # no execution_id set
    assert "execution_id" not in d  # omit-when-None → byte-identical pre-0043


def test_host_emits_one_shared_execution_id_across_lifecycle():
    """Emission wiring (proposal 0043): the live pipeline stamps ONE execution_id shared by
    execution_started + execution_completed of an attempt, distinct from invocation_id."""
    import asyncio

    from chp_core import (
        CapabilityDescriptor,
        CorrelationContext,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    async def handler(_ctx, _payload):
        return {"ok": True}

    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="svc.do", version="1.0.0", description="x"), handler)
    asyncio.run(host.ainvoke("svc.do", {"a": 1}, correlation=CorrelationContext(correlation_id="c")))

    events = host.replay("c")
    lifecycle = [e for e in events if e["event_type"] in ("execution_started", "execution_completed")]
    exec_ids = {e["execution_id"] for e in lifecycle}
    assert len(lifecycle) == 2
    assert len(exec_ids) == 1  # one execution_id for the whole attempt
    (eid,) = exec_ids
    assert eid.startswith("exec")
    assert eid != lifecycle[0]["invocation_id"]  # distinct from invocation_id (CHP-CORE-012)


def test_handler_raising_indeterminate_records_indeterminate_not_failure():
    """Emission (proposal 0043, CHP-CORE-014): a handler that raises IndeterminateExecution
    (crashed after an irreversible dispatch) yields outcome=indeterminate on an
    execution_indeterminate event — never execution_failed/completed, never success."""
    import asyncio

    from chp_core import (
        CapabilityDescriptor,
        CorrelationContext,
        IndeterminateExecution,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    async def handler(_ctx, _payload):
        raise IndeterminateExecution("dispatched migration, lost connection before confirm")

    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="svc.migrate", version="1.0.0", description="x"), handler)
    result = asyncio.run(host.ainvoke("svc.migrate", {}, correlation=CorrelationContext(correlation_id="c")))

    assert result.outcome == "indeterminate"
    assert result.success is False
    seq = [e["event_type"] for e in host.replay("c")]
    assert "execution_indeterminate" in seq
    assert "execution_completed" not in seq and "execution_failed" not in seq
    indet = next(e for e in host.replay("c") if e["event_type"] == "execution_indeterminate")
    assert indet["outcome"] == "indeterminate"
    assert indet["execution_id"].startswith("exec")


def test_stream_handler_raising_indeterminate_records_indeterminate():
    """The streaming path also treats IndeterminateExecution as indeterminate, not failure
    (proposal 0043, CHP-CORE-014)."""
    import asyncio

    from chp_core import (
        CapabilityDescriptor,
        CorrelationContext,
        IndeterminateExecution,
        InvocationEnvelope,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
    )

    async def handler(_ctx, _payload):
        for _ in ():  # never yields, but makes this an async generator (streaming)
            yield {}
        raise IndeterminateExecution("streamed, dispatched, unconfirmed")

    host = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"))
    host.register(
        CapabilityDescriptor(id="svc.stream", version="1.0.0", description="x", modes=["stream"]),
        handler,
    )
    env = InvocationEnvelope(capability_id="svc.stream", mode="stream", payload={},
                             correlation=CorrelationContext(correlation_id="c"))

    async def run():
        return [item async for item in host.ainvoke_stream(env)]

    results = asyncio.run(run())
    assert results[-1]["result"].outcome == "indeterminate"
    seq = [e["event_type"] for e in host.replay("c")]
    assert "execution_indeterminate" in seq
    assert "execution_failed" not in seq
