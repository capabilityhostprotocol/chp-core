"""Tests for chp-adapter-jobs — real ThreadPoolExecutor + host.ainvoke round-trip."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from chp_adapter_jobs import JobsAdapter, JobsConfig
from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# A target capability for jobs to run
# ---------------------------------------------------------------------------

class WorkAdapter(BaseAdapter):
    adapter_id = "chp.adapters.work"
    adapter_name = "Work"
    adapter_description = "A small target capability for jobs tests."
    adapter_category = "execution"

    @capability(
        id="chp.adapters.work.echo",
        version="1.0.0",
        description="Sleep briefly then return the input uppercased.",
        category="execution",
        risk="low",
        emits=["work_done"],
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}, "fail": {"type": "boolean"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    )
    async def echo(self, ctx: Any, payload: dict) -> dict:
        await asyncio.sleep(0.2)
        if payload.get("fail"):
            raise RuntimeError("intentional failure")
        ctx.emit("work_done", {"length": len(payload["text"])}, redacted=False)
        return {"shouted": payload["text"].upper()}


def _make_host(allowed=None, store_path=":memory:") -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, WorkAdapter())
    register_adapter(host, JobsAdapter(JobsConfig(allowed_capabilities=allowed, store_path=store_path)))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


def _wait_for(host, job_id, target_status="completed", timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _invoke(host, "chp.adapters.jobs.status", {"job_id": job_id})
        if r.data["status"] in ("completed", "failed"):
            return r.data["status"]
        time.sleep(0.1)
    return "timeout"


class TestSubmitAndResult:
    def test_submit_returns_job_id_immediately(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "hello"},
        })
        assert r.success
        assert r.data["job_id"].startswith("job_")
        assert r.data["status"] == "submitted"

    def test_job_completes_with_result(self):
        host = _make_host()
        job = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "hello world"},
        }).data
        assert _wait_for(host, job["job_id"]) == "completed"
        res = _invoke(host, "chp.adapters.jobs.result", {"job_id": job["job_id"]}).data
        assert res["ready"] is True
        assert res["success"] is True
        assert res["result"] == {"shouted": "HELLO WORLD"}

    def test_running_job_not_ready(self):
        host = _make_host()
        job = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "x"},
        }).data
        # immediately — should still be submitted/running
        res = _invoke(host, "chp.adapters.jobs.result", {"job_id": job["job_id"]}).data
        if not res["ready"]:
            assert res["status"] in ("submitted", "running")
        _wait_for(host, job["job_id"])

    def test_failed_job_records_error(self):
        host = _make_host()
        job = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "x", "fail": True},
        }).data
        assert _wait_for(host, job["job_id"]) == "failed"
        res = _invoke(host, "chp.adapters.jobs.result", {"job_id": job["job_id"]}).data
        assert res["success"] is False
        assert res["error"]


class TestPayloadRedaction:
    def test_target_payload_not_in_jobs_evidence(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "SECRET_JOB_INPUT_55"},
        })
        replay = host.replay(r.invocation_id)
        for evt in replay:
            assert "SECRET_JOB_INPUT_55" not in str(evt.get("payload", {}))
        _wait_for(host, r.data["job_id"])


class TestListAndAllowlist:
    def test_list_jobs(self):
        host = _make_host()
        _invoke(host, "chp.adapters.jobs.submit", {"capability_id": "chp.adapters.work.echo", "payload": {"text": "a"}})
        r = _invoke(host, "chp.adapters.jobs.list", {})
        assert r.data["job_count"] >= 1

    def test_disallowed_capability_rejected(self):
        host = _make_host(allowed=["chp.adapters.other.thing"])
        r = _invoke(host, "chp.adapters.jobs.submit", {
            "capability_id": "chp.adapters.work.echo", "payload": {"text": "x"},
        })
        assert not r.success

    def test_unknown_job_id_errors(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.jobs.status", {"job_id": "job_doesnotexist"})
        assert not r.success


class TestPersistence:
    def test_store_reconciles_interrupted_on_restart(self, tmp_path):
        from chp_adapter_jobs._store import JobStore
        sp = str(tmp_path / "jobs.sqlite")
        s1 = JobStore(sp)
        s1.create("job_x", "chp.adapters.work.echo")
        s1.mark_running("job_x")  # process "dies" mid-run
        # new process / new adapter instance against the same store
        s2 = JobStore(sp)
        assert s2.reconcile_interrupted() == 1
        assert s2.get_summary("job_x")["status"] == "interrupted"

    def test_completed_job_persists_across_instances(self, tmp_path):
        from chp_adapter_jobs._store import JobStore
        sp = str(tmp_path / "jobs.sqlite")
        s1 = JobStore(sp)
        s1.create("job_y", "c")
        s1.mark_done("job_y", success=True, result={"k": "v"}, error=None)
        # re-open (simulated restart) — completed result is still there
        r = JobStore(sp).get_result("job_y")
        assert r["status"] == "completed"
        assert r["success"] is True
        assert r["result"] == {"k": "v"}

    def test_adapter_reconciles_on_construction(self, tmp_path):
        from chp_adapter_jobs._store import JobStore
        sp = str(tmp_path / "jobs.sqlite")
        # leave a running job behind
        JobStore(sp).create("job_z", "chp.adapters.work.echo")
        JobStore(sp).mark_running("job_z")
        # constructing a fresh host (new JobsAdapter) reconciles it
        host = _make_host(store_path=sp)
        st = _invoke(host, "chp.adapters.jobs.status", {"job_id": "job_z"}).data
        assert st["status"] == "interrupted"


class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_jobs.adapter as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"JobsAdapter has conformance violations: {violations}"
