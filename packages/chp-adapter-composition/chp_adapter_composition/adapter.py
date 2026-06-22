"""CompositionAdapter — define and run named capability workflows as CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Step ``payload`` — NOT in evidence (may contain secrets/PII).
* Step result ``data`` — NOT in evidence.
* Only ``step_id``, ``capability_id``, ``success``, ``duration_ms``, workflow
  name and aggregate counts are recorded.

Workflow definitions are stored in-memory. ``on_register(host)`` captures the
host reference so ``run`` can call back via ``await self._host.ainvoke()``.

Four capabilities: define, run, list, get.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "workflow_defined",
    "workflow_run_started",
    "workflow_step_started",
    "workflow_step_completed",
    "workflow_step_failed",
    "workflow_run_complete",
    "workflow_run_failed",
]


@dataclass
class WorkflowStep:
    step_id: str
    capability_id: str
    payload: dict
    skip_on_failure: bool = False
    node: str | None = None  # affinity: prefer this node (name or role) for the step


@dataclass
class WorkflowDefinition:
    name: str
    description: str
    steps: list[WorkflowStep]


@dataclass
class CompositionConfig:
    """Config for CompositionAdapter.

    ``_store`` injects a pre-populated definition dict for tests.
    """
    _store: dict[str, WorkflowDefinition] | None = None


class CompositionAdapter(BaseAdapter):
    """Compose CHP capabilities into named reusable workflows."""

    adapter_id = "chp.adapters.composition"
    adapter_name = "Composition"
    adapter_description = "Define and execute named multi-step capability workflows."
    adapter_category = "core"
    adapter_tags = ["workflow", "composition", "orchestration"]

    def __init__(self, config: CompositionConfig | None = None) -> None:
        self._config = config or CompositionConfig()
        self._workflows: dict[str, WorkflowDefinition] = (
            dict(self._config._store) if self._config._store else {}
        )
        self._host: Any = None

    def on_register(self, host: Any) -> None:
        self._host = host

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.composition.define",
        version="1.0.0",
        description="Register a named workflow (sequence of capability invocations).",
        category="core",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1,
                         "description": "Unique workflow name."},
                "description": {"type": "string"},
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "step_id": {"type": "string"},
                            "capability_id": {"type": "string", "minLength": 1},
                            "payload": {"type": "object"},
                            "skip_on_failure": {"type": "boolean"},
                            "node": {"type": "string",
                                     "description": "Affinity: prefer this node (name or role) for the step."},
                        },
                        "required": ["capability_id"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["name", "steps"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["workflow"],
    )
    async def define(self, ctx: Any, payload: dict) -> dict:
        name = payload["name"]
        description = payload.get("description", "")
        raw_steps = payload["steps"]

        steps = []
        for i, s in enumerate(raw_steps):
            steps.append(WorkflowStep(
                step_id=s.get("step_id") or f"step_{i + 1}",
                capability_id=s["capability_id"],
                payload=s.get("payload") or {},
                skip_on_failure=bool(s.get("skip_on_failure", False)),
                node=s.get("node") or None,
            ))

        self._workflows[name] = WorkflowDefinition(
            name=name, description=description, steps=steps
        )

        ctx.emit("workflow_defined", {
            "name": name,
            "step_count": len(steps),
            "step_ids": [s.step_id for s in steps],
            "capability_ids": [s.capability_id for s in steps],
            # payloads intentionally not recorded
        })
        return {"name": name, "step_count": len(steps), "defined": True}

    @capability(
        id="chp.adapters.composition.run",
        version="1.0.0",
        description="Execute a registered workflow by name.",
        category="core",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Registered workflow name."},
                "workflow_id": {"type": "string",
                                "description": "Optional correlation ID for this run."},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["workflow"],
    )
    async def run(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            raise RuntimeError("CompositionAdapter must be registered with a host before run()")

        name = payload["name"]
        workflow_id = payload.get("workflow_id") or f"wfrun_{name}"

        wf = self._workflows.get(name)
        if wf is None:
            raise KeyError(f"Workflow {name!r} is not defined")

        ctx.emit("workflow_run_started", {
            "workflow_id": workflow_id,
            "name": name,
            "step_count": len(wf.steps),
        })

        step_results = []
        run_start = time.perf_counter()

        for step in wf.steps:
            ctx.emit("workflow_step_started", {
                "workflow_id": workflow_id,
                "step_id": step.step_id,
                "capability_id": step.capability_id,
                "node": step.node,  # affinity target (None if unpinned)
                # payload intentionally not recorded
            })
            t0 = time.perf_counter()
            step_error: str | None = None
            success = False
            try:
                # Affinity rides in metadata; the router honors it (a single-host
                # backend simply ignores it).
                result = await self._host.ainvoke(
                    step.capability_id,
                    step.payload,
                    correlation={"correlation_id": ctx.correlation_id},
                    metadata={"prefer": step.node} if step.node else None,
                )
                dur = round((time.perf_counter() - t0) * 1000, 2)
                success = result.success
                if not success:
                    step_error = str(result.error) if result.error else "step returned non-success"
            except Exception as exc:
                dur = round((time.perf_counter() - t0) * 1000, 2)
                step_error = str(exc)

            if success:
                ctx.emit("workflow_step_completed", {
                    "workflow_id": workflow_id,
                    "step_id": step.step_id,
                    "capability_id": step.capability_id,
                    "duration_ms": dur,
                    # result data intentionally not recorded
                })
            else:
                ctx.emit("workflow_step_failed", {
                    "workflow_id": workflow_id,
                    "step_id": step.step_id,
                    "capability_id": step.capability_id,
                    "error": step_error,
                    "duration_ms": dur,
                })
                if not step.skip_on_failure:
                    ctx.emit("workflow_run_failed", {
                        "workflow_id": workflow_id,
                        "failed_at_step": step.step_id,
                        "error": step_error,
                    })
                    raise RuntimeError(
                        f"Workflow {name!r} failed at step {step.step_id!r}: {step_error}"
                    )

            step_results.append({
                "step_id": step.step_id,
                "capability_id": step.capability_id,
                "success": success,
                "error": step_error,
                "duration_ms": dur,
            })

        total_ms = round((time.perf_counter() - run_start) * 1000, 2)
        completed = sum(1 for s in step_results if s["success"])
        failed = sum(1 for s in step_results if not s["success"])

        ctx.emit("workflow_run_complete", {
            "workflow_id": workflow_id,
            "name": name,
            "completed_steps": completed,
            "failed_steps": failed,
            "total_duration_ms": total_ms,
        })

        return {
            "workflow_id": workflow_id,
            "name": name,
            "steps": step_results,
            "completed_steps": completed,
            "failed_steps": failed,
            "total_duration_ms": total_ms,
        }

    @capability(
        id="chp.adapters.composition.list",
        version="1.0.0",
        description="List all registered workflows.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["workflow"],
    )
    async def list_workflows(self, ctx: Any, payload: dict) -> dict:
        workflows = [
            {
                "name": wf.name,
                "description": wf.description,
                "step_count": len(wf.steps),
            }
            for wf in self._workflows.values()
        ]
        ctx.emit("workflows_listed", {"count": len(workflows)}, redacted=False)
        return {"workflows": workflows, "count": len(workflows)}

    @capability(
        id="chp.adapters.composition.get",
        version="1.0.0",
        description="Get a workflow definition by name.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["workflow"],
    )
    async def get_workflow(self, ctx: Any, payload: dict) -> dict:
        name = payload["name"]
        wf = self._workflows.get(name)
        if wf is None:
            raise KeyError(f"Workflow {name!r} is not defined")
        ctx.emit("workflow_retrieved", {"name": name, "step_count": len(wf.steps)}, redacted=False)
        return {
            "name": wf.name,
            "description": wf.description,
            "steps": [
                {
                    "step_id": s.step_id,
                    "capability_id": s.capability_id,
                    "skip_on_failure": s.skip_on_failure,
                    # payload intentionally not returned (may contain secrets)
                }
                for s in wf.steps
            ],
            "step_count": len(wf.steps),
        }
