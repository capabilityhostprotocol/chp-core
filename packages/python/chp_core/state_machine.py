"""Governed state machine capability for CHP v0.5.0 (§6.3)."""

from __future__ import annotations

from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    StateMachineDefinition,
    StateMachineRecord,
    StateMachineStatus,
    StateMachineTransitionResult,
    new_id,
    utc_now,
)

_SM_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "state_machine_created",
    "state_machine_transition_started",
    "state_machine_transition_completed",
    "state_machine_blocked",
    "state_machine_completed",
    "state_machine_failed",
    "state_machine_cancelled",
]


class StateMachineCapability:
    capability_id_prefix: str = "state_machine"
    capability_version: str = "0.1.0"
    description: str = "Governed state machine with explicit lifecycle management."

    def create(self, name: str, definition: StateMachineDefinition, context: dict) -> StateMachineRecord:
        raise NotImplementedError

    def transition(self, machine_id: str, event: str) -> StateMachineTransitionResult:
        raise NotImplementedError

    def get(self, machine_id: str) -> StateMachineRecord | None:
        raise NotImplementedError

    def list_machines(self, *, status: StateMachineStatus | None = None) -> list[StateMachineRecord]:
        raise NotImplementedError


class InMemoryStateMachine(StateMachineCapability):
    def __init__(
        self,
        *,
        capability_id_prefix: str = "state_machine",
        capability_version: str = "0.1.0",
        description: str = "In-memory state machine.",
    ) -> None:
        self.capability_id_prefix = capability_id_prefix
        self.capability_version = capability_version
        self.description = description
        self._machines: dict[str, StateMachineRecord] = {}

    def create(self, name: str, definition: StateMachineDefinition, context: dict) -> StateMachineRecord:
        if definition.initial_state not in definition.states:
            raise ValueError(f"initial_state {definition.initial_state!r} not in states")
        for terminal in definition.terminal_states:
            if terminal not in definition.states:
                raise ValueError(f"terminal_state {terminal!r} not in states")
        now = utc_now()
        record = StateMachineRecord(
            machine_id=new_id("sm"),
            name=name,
            definition=definition,
            current_state=definition.initial_state,
            status="queued",
            context=dict(context),
            created_at=now,
            updated_at=now,
            history=[],
        )
        self._machines[record.machine_id] = record
        return record

    def transition(self, machine_id: str, event: str) -> StateMachineTransitionResult:
        record = self._machines.get(machine_id)
        if record is None:
            return StateMachineTransitionResult(
                machine_id=machine_id,
                from_state="",
                to_state="",
                event=event,
                allowed=False,
                reason=f"machine {machine_id!r} not found",
                updated_at=utc_now(),
            )
        if record.status in ("done", "failed", "cancelled"):
            return StateMachineTransitionResult(
                machine_id=machine_id,
                from_state=record.current_state,
                to_state=record.current_state,
                event=event,
                allowed=False,
                reason=f"machine is terminal (status={record.status!r})",
                updated_at=utc_now(),
            )
        allowed_next = record.definition.transitions.get(record.current_state, [])
        # event is treated as the target state name
        if event not in allowed_next:
            return StateMachineTransitionResult(
                machine_id=machine_id,
                from_state=record.current_state,
                to_state=event,
                event=event,
                allowed=False,
                reason=f"transition {record.current_state!r} → {event!r} not defined",
                updated_at=utc_now(),
            )
        from_state = record.current_state
        now = utc_now()
        record.history.append({"from": from_state, "to": event, "event": event, "at": now})
        record.current_state = event
        record.updated_at = now
        if event in record.definition.terminal_states:
            record.status = "done" if event not in ("failed", "cancelled") else event  # type: ignore[assignment]
        else:
            record.status = "running"
        return StateMachineTransitionResult(
            machine_id=machine_id,
            from_state=from_state,
            to_state=event,
            event=event,
            allowed=True,
            reason=None,
            updated_at=now,
        )

    def get(self, machine_id: str) -> StateMachineRecord | None:
        return self._machines.get(machine_id)

    def list_machines(self, *, status: StateMachineStatus | None = None) -> list[StateMachineRecord]:
        machines = list(self._machines.values())
        if status is not None:
            machines = [m for m in machines if m.status == status]
        return machines


def register_state_machine_capability(host: Any, sm: StateMachineCapability | None = None) -> None:
    sm = sm or InMemoryStateMachine()
    prefix = sm.capability_id_prefix
    version = sm.capability_version

    # ── state_machine.create ─────────────────────────────────────────────────

    create_desc = CapabilityDescriptor(
        id=f"{prefix}.create",
        version=version,
        description="Create a new state machine instance from a definition.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["state_machine"],
        emits=list(_SM_EMITS),
    )

    async def _create(ctx, payload) -> dict:
        name: str = payload.get("name", "unnamed")
        defn_raw: dict = payload.get("definition") or {}
        context: dict = payload.get("context") or {}

        definition = StateMachineDefinition(
            states=defn_raw.get("states", []),
            transitions=defn_raw.get("transitions", {}),
            initial_state=defn_raw.get("initial_state", ""),
            terminal_states=defn_raw.get("terminal_states", []),
        )
        ctx.emit("execution_started", {"capability_id": create_desc.id}, redacted=False)
        try:
            record = sm.create(name, definition, context)
        except Exception as exc:
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        ctx.emit("state_machine_created", {"machine_id": record.machine_id, "initial_state": record.current_state}, redacted=False)
        ctx.emit("execution_completed", {"capability_id": create_desc.id, "outcome": "success"}, redacted=False)
        return record.to_dict()

    host.register(create_desc, _create)

    # ── state_machine.transition ─────────────────────────────────────────────

    transition_desc = CapabilityDescriptor(
        id=f"{prefix}.transition",
        version=version,
        description="Fire an event to transition a state machine to its next state.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["state_machine"],
        emits=list(_SM_EMITS),
    )

    async def _transition(ctx, payload) -> dict:
        machine_id: str = payload.get("machine_id", "")
        event: str = payload.get("event", "")

        ctx.emit("execution_started", {"capability_id": transition_desc.id}, redacted=False)
        ctx.emit("state_machine_transition_started", {"machine_id": machine_id, "event": event}, redacted=False)
        try:
            result = sm.transition(machine_id, event)
        except Exception as exc:
            ctx.emit("execution_failed", {"error": str(exc)}, redacted=False)
            raise
        if result.allowed:
            record = sm.get(machine_id)
            status = record.status if record else "unknown"
            if status == "done":
                ctx.emit("state_machine_completed", {"machine_id": machine_id, "final_state": result.to_state}, redacted=False)
            elif status == "failed":
                ctx.emit("state_machine_failed", {"machine_id": machine_id, "final_state": result.to_state}, redacted=False)
            elif status == "cancelled":
                ctx.emit("state_machine_cancelled", {"machine_id": machine_id, "final_state": result.to_state}, redacted=False)
            else:
                ctx.emit("state_machine_transition_completed", {"machine_id": machine_id, "from": result.from_state, "to": result.to_state}, redacted=False)
        else:
            ctx.emit("state_machine_blocked", {"machine_id": machine_id, "reason": result.reason}, redacted=False)
        ctx.emit("execution_completed", {"capability_id": transition_desc.id, "outcome": "success"}, redacted=False)
        return result.to_dict()

    host.register(transition_desc, _transition)

    # ── state_machine.get ────────────────────────────────────────────────────

    get_desc = CapabilityDescriptor(
        id=f"{prefix}.get",
        version=version,
        description="Retrieve current state and history of a state machine instance.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["state_machine"],
        emits=["execution_started", "execution_completed", "execution_failed"],
    )

    async def _get(ctx, payload) -> dict:
        machine_id: str = payload.get("machine_id", "")
        ctx.emit("execution_started", {"capability_id": get_desc.id}, redacted=False)
        record = sm.get(machine_id)
        ctx.emit("execution_completed", {"capability_id": get_desc.id, "outcome": "success"}, redacted=False)
        return record.to_dict() if record else {}

    host.register(get_desc, _get)

    # ── state_machine.list ───────────────────────────────────────────────────

    list_desc = CapabilityDescriptor(
        id=f"{prefix}.list",
        version=version,
        description="List all state machine instances, optionally filtered by status.",
        category=CapabilityCategory.PROCESS_WORKFLOW,
        tags=["state_machine"],
        emits=["execution_started", "execution_completed", "execution_failed"],
    )

    async def _list(ctx, payload) -> dict:
        status_filter: StateMachineStatus | None = payload.get("status")
        ctx.emit("execution_started", {"capability_id": list_desc.id}, redacted=False)
        machines = sm.list_machines(status=status_filter)
        ctx.emit("execution_completed", {"capability_id": list_desc.id, "outcome": "success"}, redacted=False)
        return {"machines": [m.to_dict() for m in machines], "count": len(machines)}

    host.register(list_desc, _list)
