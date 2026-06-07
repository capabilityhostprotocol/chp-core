"""Governed workflow orchestration capability for CHP v0.4.4."""

from __future__ import annotations

from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    WorkflowResult,
    WorkflowStepResult,
    new_id,
)

_WORKFLOW_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "workflow_started",
    "workflow_step_started",
    "workflow_step_completed",
    "workflow_step_failed",
    "workflow_completed",
    "workflow_failed",
]


class WorkflowCapability:
    capability_id: str = "workflow.run"
    capability_version: str = "0.1.0"
    description: str = "Governed sequential workflow executor."


class InMemoryWorkflow(WorkflowCapability):
    """Stateless workflow executor — all logic is in the register handler."""

    def __init__(
        self,
        *,
        capability_id: str = "workflow.run",
        capability_version: str = "0.1.0",
        description: str = "Governed sequential workflow executor.",
    ) -> None:
        self.capability_id = capability_id
        self.capability_version = capability_version
        self.description = description


def register_workflow_capability(
    host: Any,
    wf: WorkflowCapability | None = None,
) -> None:
    wf = wf or WorkflowCapability()

    desc = CapabilityDescriptor(
        id=wf.capability_id,
        version=wf.capability_version,
        description=wf.description,
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["workflow"],
        emits=list(_WORKFLOW_EMITS),
    )

    async def _run_workflow(ctx, payload) -> dict:
        import time

        workflow_id = payload.get("workflow_id") or new_id("wf")
        name: str | None = payload.get("name")
        raw_steps: list[dict] = payload.get("steps") or []

        ctx.emit(
            "execution_started",
            {"capability_id": desc.id, "capability_version": desc.version},
            redacted=False,
        )
        ctx.emit(
            "workflow_started",
            {"workflow_id": workflow_id, "name": name, "step_count": len(raw_steps)},
            redacted=False,
        )

        step_results: list[WorkflowStepResult] = []
        total_start = time.perf_counter()

        for raw in raw_steps:
            step_id: str = raw.get("step_id") or new_id("step")
            cap_id: str = raw.get("capability_id", "")
            step_payload: dict = raw.get("payload") or {}
            skip: bool = bool(raw.get("skip_on_failure", False))

            ctx.emit(
                "workflow_step_started",
                {"workflow_id": workflow_id, "step_id": step_id, "capability_id": cap_id},
                redacted=False,
            )
            t0 = time.perf_counter()
            step_error: str | None = None
            step_success = False
            step_data: dict = {}
            try:
                result = await ctx.host.ainvoke(
                    cap_id,
                    step_payload,
                    correlation={"correlation_id": ctx.correlation_id},
                )
                dur = round((time.perf_counter() - t0) * 1000, 2)
                step_success = result.success
                if result.success:
                    step_data = result.data or {}
                else:
                    step_error = str(result.error) if result.error else "step failed"
            except Exception as exc:
                dur = round((time.perf_counter() - t0) * 1000, 2)
                step_error = str(exc)

            if step_success:
                ctx.emit(
                    "workflow_step_completed",
                    {
                        "workflow_id": workflow_id,
                        "step_id": step_id,
                        "success": True,
                        "duration_ms": dur,
                    },
                    redacted=False,
                )
                step_results.append(
                    WorkflowStepResult(
                        step_id=step_id,
                        capability_id=cap_id,
                        success=True,
                        data=step_data,
                        duration_ms=dur,
                    )
                )
            else:
                ctx.emit(
                    "workflow_step_failed",
                    {
                        "workflow_id": workflow_id,
                        "step_id": step_id,
                        "error": step_error,
                        "duration_ms": dur,
                    },
                    redacted=False,
                )
                step_results.append(
                    WorkflowStepResult(
                        step_id=step_id,
                        capability_id=cap_id,
                        success=False,
                        error=step_error,
                        duration_ms=dur,
                    )
                )
                if not skip:
                    ctx.emit(
                        "workflow_failed",
                        {
                            "workflow_id": workflow_id,
                            "failed_at_step": step_id,
                            "error": step_error,
                        },
                        redacted=False,
                    )
                    ctx.emit("execution_failed", {"error": step_error}, redacted=False)
                    raise RuntimeError(f"step {step_id!r} failed: {step_error}")

        total_ms = round((time.perf_counter() - total_start) * 1000, 2)
        done = sum(1 for s in step_results if s.success)
        failed = sum(1 for s in step_results if not s.success)
        ctx.emit(
            "workflow_completed",
            {
                "workflow_id": workflow_id,
                "completed_steps": done,
                "failed_steps": failed,
                "total_duration_ms": total_ms,
            },
            redacted=False,
        )
        ctx.emit(
            "execution_completed",
            {"capability_id": desc.id, "outcome": "success"},
            redacted=False,
        )
        return WorkflowResult(
            workflow_id=workflow_id,
            name=name,
            steps=step_results,
            completed_steps=done,
            failed_steps=failed,
            total_duration_ms=total_ms,
        ).to_dict()

    host.register(desc, _run_workflow)
