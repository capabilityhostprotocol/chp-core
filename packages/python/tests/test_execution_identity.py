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
