"""Tests for chp_adapter_composition.adapter — uses a fake host to avoid live invocations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_composition import CompositionAdapter, CompositionConfig


# --------------------------------------------------------------------------
# Fake host helpers
# --------------------------------------------------------------------------

@dataclass
class FakeResult:
    success: bool
    data: Any = None
    error: Any = None
    outcome: str = "success"


class FakeHost:
    """Minimal host stub for testing CompositionAdapter without a real host."""

    def __init__(self, responses: dict[str, FakeResult] | None = None) -> None:
        self._responses: dict[str, FakeResult] = responses or {}
        self.calls: list[tuple[str, dict]] = []

    async def ainvoke(self, capability_id: str, payload: dict, **_kw) -> FakeResult:
        self.calls.append((capability_id, payload))
        result = self._responses.get(capability_id)
        if result is None:
            return FakeResult(success=True, data={}, outcome="success")
        return result


def _make_real_host(adapter: CompositionAdapter) -> LocalCapabilityHost:
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


# --------------------------------------------------------------------------
# 1. Capability shaping
# --------------------------------------------------------------------------

class TestCapabilityShaping:
    def test_capability_ids(self):
        adapter = CompositionAdapter()
        ids = {c.descriptor.id for c in adapter.capabilities()}
        assert ids == {
            "chp.adapters.composition.define",
            "chp.adapters.composition.run",
            "chp.adapters.composition.list",
            "chp.adapters.composition.get",
        }

    def test_adapter_id(self):
        assert CompositionAdapter().adapter_id == "chp.adapters.composition"

    def test_define_is_medium_risk(self):
        adapter = CompositionAdapter()
        cap = next(c for c in adapter.capabilities()
                   if c.descriptor.id == "chp.adapters.composition.define")
        assert cap.descriptor.risk == "medium"

    def test_run_is_medium_risk(self):
        adapter = CompositionAdapter()
        cap = next(c for c in adapter.capabilities()
                   if c.descriptor.id == "chp.adapters.composition.run")
        assert cap.descriptor.risk == "medium"

    def test_list_is_low_risk(self):
        adapter = CompositionAdapter()
        cap = next(c for c in adapter.capabilities()
                   if c.descriptor.id == "chp.adapters.composition.list")
        assert cap.descriptor.risk == "low"

    def test_get_is_low_risk(self):
        adapter = CompositionAdapter()
        cap = next(c for c in adapter.capabilities()
                   if c.descriptor.id == "chp.adapters.composition.get")
        assert cap.descriptor.risk == "low"


# --------------------------------------------------------------------------
# 2. define capability
# --------------------------------------------------------------------------

class TestDefine:
    def test_define_returns_name_and_step_count(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "name": "wf1",
            "steps": [{"capability_id": "some.cap"}],
        })
        assert r.outcome == "success"
        assert r.data["name"] == "wf1"
        assert r.data["step_count"] == 1
        assert r.data["defined"] is True

    def test_define_multiple_steps(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "name": "multi",
            "steps": [
                {"capability_id": "a.cap"},
                {"capability_id": "b.cap"},
                {"capability_id": "c.cap"},
            ],
        })
        assert r.data["step_count"] == 3

    def test_define_auto_generates_step_ids(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "name": "wfauto",
            "steps": [{"capability_id": "x"}, {"capability_id": "y"}],
        })
        # The workflow is stored — verify via get
        rg = host.invoke("chp.adapters.composition.get", {"name": "wfauto"})
        step_ids = [s["step_id"] for s in rg.data["steps"]]
        assert step_ids == ["step_1", "step_2"]

    def test_define_explicit_step_ids_preserved(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "explicit",
            "steps": [{"capability_id": "a", "step_id": "fetch"}, {"capability_id": "b", "step_id": "transform"}],
        })
        rg = host.invoke("chp.adapters.composition.get", {"name": "explicit"})
        ids = [s["step_id"] for s in rg.data["steps"]]
        assert ids == ["fetch", "transform"]

    def test_define_empty_steps_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "name": "bad",
            "steps": [],
        })
        assert r.outcome == "denied"

    def test_define_missing_name_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "steps": [{"capability_id": "a"}],
        })
        assert r.outcome == "denied"

    def test_define_unknown_field_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.define", {
            "name": "wf",
            "steps": [{"capability_id": "a"}],
            "bogus": True,
        })
        assert r.outcome == "denied"

    def test_define_overwrites_existing(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "wf",
            "steps": [{"capability_id": "a"}],
        })
        host.invoke("chp.adapters.composition.define", {
            "name": "wf",
            "steps": [{"capability_id": "b"}, {"capability_id": "c"}],
        })
        rg = host.invoke("chp.adapters.composition.get", {"name": "wf"})
        assert rg.data["step_count"] == 2

    def test_define_emits_workflow_defined(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "wf_ev",
            "steps": [{"capability_id": "cap.x"}],
        })
        events = [e for e in host.store.all()
                  if e["event_type"] == "workflow_defined"]
        assert len(events) == 1
        assert events[0]["payload"]["name"] == "wf_ev"

    def test_define_payload_not_in_evidence(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "sensitive_wf",
            "steps": [{"capability_id": "cap", "payload": {"secret_key": "hunter2"}}],
        })
        dump = str([e["payload"] for e in host.store.all()])
        assert "hunter2" not in dump


# --------------------------------------------------------------------------
# 3. list capability
# --------------------------------------------------------------------------

class TestList:
    def test_list_empty_initially(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.list", {})
        assert r.outcome == "success"
        assert r.data["count"] == 0
        assert r.data["workflows"] == []

    def test_list_after_define(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "wf1",
            "description": "First workflow",
            "steps": [{"capability_id": "cap.a"}],
        })
        host.invoke("chp.adapters.composition.define", {
            "name": "wf2",
            "steps": [{"capability_id": "cap.b"}, {"capability_id": "cap.c"}],
        })
        r = host.invoke("chp.adapters.composition.list", {})
        assert r.data["count"] == 2
        names = {w["name"] for w in r.data["workflows"]}
        assert names == {"wf1", "wf2"}

    def test_list_includes_step_count(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "three_step",
            "steps": [{"capability_id": "a"}, {"capability_id": "b"}, {"capability_id": "c"}],
        })
        r = host.invoke("chp.adapters.composition.list", {})
        wf = next(w for w in r.data["workflows"] if w["name"] == "three_step")
        assert wf["step_count"] == 3

    def test_list_unknown_field_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.list", {"extra": True})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 4. get capability
# --------------------------------------------------------------------------

class TestGet:
    def test_get_existing_workflow(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "fetch_wf",
            "description": "Fetches stuff",
            "steps": [
                {"capability_id": "cap.a", "step_id": "a"},
                {"capability_id": "cap.b", "step_id": "b", "skip_on_failure": True},
            ],
        })
        r = host.invoke("chp.adapters.composition.get", {"name": "fetch_wf"})
        assert r.outcome == "success"
        assert r.data["name"] == "fetch_wf"
        assert r.data["description"] == "Fetches stuff"
        assert r.data["step_count"] == 2
        steps = r.data["steps"]
        assert steps[0]["step_id"] == "a"
        assert steps[1]["skip_on_failure"] is True

    def test_get_payload_not_returned(self):
        host = _make_real_host(CompositionAdapter())
        host.invoke("chp.adapters.composition.define", {
            "name": "secret_wf",
            "steps": [{"capability_id": "cap", "payload": {"token": "abc123"}}],
        })
        r = host.invoke("chp.adapters.composition.get", {"name": "secret_wf"})
        dump = str(r.data)
        assert "abc123" not in dump
        # Steps should not include payload key
        assert "payload" not in r.data["steps"][0]

    def test_get_undefined_workflow_fails(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.get", {"name": "not_here"})
        assert r.outcome == "failure"

    def test_get_missing_name_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.get", {})
        assert r.outcome == "denied"

    def test_get_unknown_field_denied(self):
        host = _make_real_host(CompositionAdapter())
        r = host.invoke("chp.adapters.composition.get", {"name": "wf", "extra": True})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 5. run capability — async, uses fake host
# --------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRun:
    async def _run_with_fake(self, wf_def: dict, responses: dict | None = None) -> tuple[Any, FakeHost]:
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        # define the workflow
        await real_host.ainvoke("chp.adapters.composition.define", wf_def)
        # now inject a fake host so ainvoke goes to our stub
        fake = FakeHost(responses or {})
        adapter._host = fake
        result = await real_host.ainvoke("chp.adapters.composition.run", {"name": wf_def["name"]})
        return result, fake

    async def test_run_all_steps_succeed(self):
        wf = {
            "name": "happy_path",
            "steps": [
                {"capability_id": "cap.a", "step_id": "a"},
                {"capability_id": "cap.b", "step_id": "b"},
            ],
        }
        r, fake = await self._run_with_fake(wf)
        assert r.outcome == "success"
        assert r.data["completed_steps"] == 2
        assert r.data["failed_steps"] == 0
        assert len(fake.calls) == 2
        assert fake.calls[0][0] == "cap.a"
        assert fake.calls[1][0] == "cap.b"

    async def test_run_step_payloads_forwarded_to_host(self):
        wf = {
            "name": "payload_wf",
            "steps": [{"capability_id": "cap.a", "payload": {"key": "val"}}],
        }
        r, fake = await self._run_with_fake(wf)
        assert fake.calls[0][1] == {"key": "val"}

    async def test_run_failing_step_halts_workflow(self):
        wf = {
            "name": "fail_wf",
            "steps": [
                {"capability_id": "cap.a", "step_id": "a"},
                {"capability_id": "cap.b", "step_id": "b"},
                {"capability_id": "cap.c", "step_id": "c"},
            ],
        }
        responses = {"cap.b": FakeResult(success=False, error="something broke", outcome="failure")}
        r, fake = await self._run_with_fake(wf, responses)
        # Halts at b — c should never be called
        assert r.outcome == "failure"
        assert len(fake.calls) == 2  # a + b; c skipped

    async def test_run_skip_on_failure_continues(self):
        wf = {
            "name": "skip_wf",
            "steps": [
                {"capability_id": "cap.a", "step_id": "a"},
                {"capability_id": "cap.b", "step_id": "b", "skip_on_failure": True},
                {"capability_id": "cap.c", "step_id": "c"},
            ],
        }
        responses = {"cap.b": FakeResult(success=False, error="non-fatal")}
        r, fake = await self._run_with_fake(wf, responses)
        assert r.outcome == "success"
        assert r.data["completed_steps"] == 2
        assert r.data["failed_steps"] == 1
        assert len(fake.calls) == 3  # all three called

    async def test_run_undefined_workflow_fails(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        fake = FakeHost()
        adapter._host = fake
        r = await real_host.ainvoke("chp.adapters.composition.run", {"name": "missing_wf"})
        assert r.outcome == "failure"

    async def test_run_missing_name_denied(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        fake = FakeHost()
        adapter._host = fake
        r = await real_host.ainvoke("chp.adapters.composition.run", {})
        assert r.outcome == "denied"

    async def test_run_unknown_field_denied(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        fake = FakeHost()
        adapter._host = fake
        r = await real_host.ainvoke("chp.adapters.composition.run", {"name": "wf", "extra": True})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 6. run evidence hygiene
# --------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRunEvidence:
    async def test_step_payload_not_in_evidence(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        await real_host.ainvoke("chp.adapters.composition.define", {
            "name": "sec_wf",
            "steps": [{"capability_id": "cap", "payload": {"secret": "topsecret"}}],
        })
        adapter._host = FakeHost()
        await real_host.ainvoke("chp.adapters.composition.run", {"name": "sec_wf"})
        dump = str([e["payload"] for e in real_host.store.all()])
        assert "topsecret" not in dump

    async def test_step_result_data_not_in_evidence(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        await real_host.ainvoke("chp.adapters.composition.define", {
            "name": "result_wf",
            "steps": [{"capability_id": "cap"}],
        })
        adapter._host = FakeHost({"cap": FakeResult(success=True, data={"private": "leaked"})})
        await real_host.ainvoke("chp.adapters.composition.run", {"name": "result_wf"})
        dump = str([e["payload"] for e in real_host.store.all()])
        assert "leaked" not in dump

    async def test_run_emits_workflow_events(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        await real_host.ainvoke("chp.adapters.composition.define", {
            "name": "ev_wf",
            "steps": [{"capability_id": "cap.a"}, {"capability_id": "cap.b"}],
        })
        adapter._host = FakeHost()
        await real_host.ainvoke("chp.adapters.composition.run", {"name": "ev_wf"})
        event_types = {e["event_type"] for e in real_host.store.all()}
        assert "workflow_run_started" in event_types
        assert "workflow_step_started" in event_types
        assert "workflow_step_completed" in event_types
        assert "workflow_run_complete" in event_types

    async def test_run_records_step_metadata(self):
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        await real_host.ainvoke("chp.adapters.composition.define", {
            "name": "meta_wf",
            "steps": [{"capability_id": "cap.x", "step_id": "my_step"}],
        })
        adapter._host = FakeHost()
        await real_host.ainvoke("chp.adapters.composition.run", {"name": "meta_wf"})
        completed = [e for e in real_host.store.all()
                     if e["event_type"] == "workflow_step_completed"]
        assert completed[0]["payload"]["step_id"] == "my_step"
        assert completed[0]["payload"]["capability_id"] == "cap.x"
        assert "duration_ms" in completed[0]["payload"]


# --------------------------------------------------------------------------
# 7. on_register hook
# --------------------------------------------------------------------------

class TestOnRegister:
    def test_host_captured_on_register(self):
        adapter = CompositionAdapter()
        fake = FakeHost()
        adapter.on_register(fake)
        assert adapter._host is fake

    def test_run_fails_without_host(self):
        # When CompositionAdapter is NOT registered with a real host
        # but _host is None, run() raises RuntimeError (failure outcome)
        adapter = CompositionAdapter()
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        # Manually clear the host ref
        adapter._host = None
        # define a workflow
        real_host.invoke("chp.adapters.composition.define", {
            "name": "orphan",
            "steps": [{"capability_id": "cap"}],
        })
        r = real_host.invoke("chp.adapters.composition.run", {"name": "orphan"})
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 8. injectable store (CompositionConfig._store)
# --------------------------------------------------------------------------

class TestInjectableStore:
    def test_pre_populated_store(self):
        from chp_adapter_composition.adapter import WorkflowDefinition, WorkflowStep
        preset = {
            "existing": WorkflowDefinition(
                name="existing",
                description="pre-built",
                steps=[WorkflowStep(step_id="s1", capability_id="cap.x", payload={})],
            )
        }
        adapter = CompositionAdapter(CompositionConfig(_store=preset))
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        r = real_host.invoke("chp.adapters.composition.get", {"name": "existing"})
        assert r.outcome == "success"
        assert r.data["description"] == "pre-built"

    def test_store_is_copied_not_shared(self):
        from chp_adapter_composition.adapter import WorkflowDefinition, WorkflowStep
        shared_store: dict = {}
        adapter = CompositionAdapter(CompositionConfig(_store=shared_store))
        real_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(real_host, adapter)
        # Add to adapter
        real_host.invoke("chp.adapters.composition.define", {
            "name": "added",
            "steps": [{"capability_id": "cap"}],
        })
        # Original dict should be unchanged
        assert "added" not in shared_store
