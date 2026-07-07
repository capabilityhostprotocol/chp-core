"""JobsAdapter — run any CHP capability as a background job.

Some capabilities are slow (e.g. huggingface.generate_image: minutes on MPS) and
outlive HTTP request timeouts. This adapter runs a target capability in a
ThreadPoolExecutor and returns a ``job_id`` immediately; callers poll ``status``
and fetch ``result`` when done.

The target capability runs via ``host.ainvoke`` inside a worker thread, so it
keeps its own full evidence chain (the SQLite evidence store is thread-safe).
This adapter emits only lightweight job-lifecycle events — never the target's
payload or result.

No backend isolation file: this adapter uses only stdlib (asyncio, concurrent
.futures) and is conformance-clean.
"""

from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

from ._store import JobStore

_EMITS = [
    "jobs_submitted",
    "jobs_status_checked",
    "jobs_result_fetched",
    "jobs_listed",
]


@dataclass
class JobsConfig:
    max_workers: int = 2
    allowed_capabilities: list[str] | None = None  # None → any capability may be submitted
    store_path: str = ""  # SQLite path; default ~/.chp/jobs.sqlite


class JobsAdapter(BaseAdapter):
    """Run any registered CHP capability as a polled background job."""

    adapter_id = "chp.adapters.jobs"
    adapter_name = "Jobs"
    adapter_description = (
        "Run any CHP capability as a background job: submit returns a job_id "
        "immediately; poll status and fetch result. For heavy/long capabilities."
    )
    adapter_category = "infrastructure"
    adapter_tags = ["jobs", "async", "background", "task", "infrastructure"]

    def __init__(self, config: JobsConfig | None = None) -> None:
        self._config = config or JobsConfig()
        self._host: Any = None
        self._executor: ThreadPoolExecutor | None = None
        self._store = JobStore(self._config.store_path)
        # Any jobs left running/submitted belonged to a previous (now-dead)
        # process whose executor did not survive — mark them interrupted so
        # pollers get a definitive state instead of waiting forever.
        self._store.reconcile_interrupted()

    def on_register(self, host: Any) -> None:
        self._host = host

    def _ensure_executor(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._config.max_workers, thread_name_prefix="chp-job"
            )
        return self._executor

    def _run_job(self, job_id: str, capability_id: str, payload: dict, correlation: Any = None) -> None:
        self._store.mark_running(job_id)
        try:
            # The job's evidence MUST ride the submitting correlation with a causal
            # edge (chp-v0.2.md §7 — deferred execution) — a fresh correlation would
            # sever the chain that governed the submit.
            result = asyncio.run(self._host.ainvoke(capability_id, payload, correlation=correlation))
            success = bool(getattr(result, "success", False))
            self._store.mark_done(
                job_id,
                success=success,
                result=result.data if success else None,
                error=None if success else (getattr(result, "error", None) or "capability failed"),
            )
        except Exception as exc:  # noqa: BLE001 — record failure on the job, don't crash the worker
            self._store.mark_done(job_id, success=False, result=None, error=str(exc)[:500])

    @capability(
        id="chp.adapters.jobs.submit",
        version="1.0.0",
        description=(
            "Submit a CHP capability to run as a background job. Returns a job_id "
            "immediately. The target keeps its own evidence chain; this adapter never "
            "records the target payload or result."
        ),
        category="infrastructure",
        provider="jobs",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "capability_id": {"type": "string", "description": "Target capability id to run"},
                "payload": {"type": "object", "description": "Payload passed to the target capability"},
            },
            "required": ["capability_id"],
            "additionalProperties": False,
        },
    )
    async def submit(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("JobsAdapter must be registered with a host (on_register).")
        capability_id: str = payload["capability_id"]
        target_payload: dict = payload.get("payload") or {}

        allowed = self._config.allowed_capabilities
        if allowed is not None and capability_id not in allowed:
            raise ValueError(f"Capability {capability_id!r} is not in allowed_capabilities.")

        job_id = "job_" + uuid.uuid4().hex[:16]
        self._store.create(job_id, capability_id)
        # Immutable CorrelationContext (not ctx itself) — safe to carry across
        # the worker thread; causation_id = this submit invocation.
        child = ctx.child_correlation()
        self._ensure_executor().submit(self._run_job, job_id, capability_id, target_payload, child)

        ctx.emit("jobs_submitted", {"job_id": job_id, "capability_id": capability_id}, redacted=False)
        return {"job_id": job_id, "capability_id": capability_id, "status": "submitted"}

    @capability(
        id="chp.adapters.jobs.status",
        version="1.0.0",
        description="Poll a background job's lifecycle state (submitted/running/completed/failed) and duration.",
        category="infrastructure",
        provider="jobs",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
            "additionalProperties": False,
        },
    )
    async def status(self, ctx: Any, payload: dict) -> dict:
        job_id = payload["job_id"]
        summary = self._store.get_summary(job_id)
        if summary is None:
            raise KeyError(f"Unknown job_id: {job_id!r}")
        ctx.emit("jobs_status_checked", {"job_id": job_id, "status": summary["status"]}, redacted=False)
        return summary

    @capability(
        id="chp.adapters.jobs.result",
        version="1.0.0",
        description="Fetch a completed job's result data. Errors if the job is still running or unknown.",
        category="infrastructure",
        provider="jobs",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
            "additionalProperties": False,
        },
    )
    async def result(self, ctx: Any, payload: dict) -> dict:
        job_id = payload["job_id"]
        res = self._store.get_result(job_id)
        if res is None:
            raise KeyError(f"Unknown job_id: {job_id!r}")
        status = res["status"]
        ctx.emit("jobs_result_fetched", {"job_id": job_id, "status": status}, redacted=False)
        if status in ("submitted", "running"):
            return {"job_id": job_id, "status": status, "ready": False}
        return {"job_id": job_id, "status": status, "ready": True, "success": res["success"],
                "result": res["result"], "error": res["error"]}

    @capability(
        id="chp.adapters.jobs.list",
        version="1.0.0",
        description="List all jobs and their lifecycle state.",
        category="infrastructure",
        provider="jobs",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def list(self, ctx: Any, payload: dict) -> dict:
        summaries = self._store.list_summaries()
        ctx.emit("jobs_listed", {"job_count": len(summaries)}, redacted=False)
        return {"jobs": summaries, "job_count": len(summaries)}
