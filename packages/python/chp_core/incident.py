"""Incident detection, lifecycle, and remediation capability for CHP §9.5."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentTrigger,
    RemediationAction,
    new_id,
    utc_now,
)

_INCIDENT_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "incident_opened",
    "incident_escalated",
    "incident_remediation_applied",
    "incident_resolved",
    "incident_closed",
    "incident_trigger_fired",
]

_VALID_TRANSITIONS: dict[IncidentStatus, list[IncidentStatus]] = {
    "open": ["investigating", "escalated", "resolved"],
    "investigating": ["escalated", "resolved"],
    "escalated": ["resolved"],
    "resolved": ["closed"],
    "closed": [],
}


class InMemoryIncidentManager:
    """Dict-backed incident store with trigger scanning."""

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._remediations: list[RemediationAction] = []

    def open(
        self,
        title: str,
        severity: IncidentSeverity,
        *,
        correlation_ids: list[str] | None = None,
        trigger: IncidentTrigger | None = None,
    ) -> Incident:
        incident = Incident(
            incident_id=new_id("inc"),
            title=title,
            severity=severity,
            status="open",
            trigger=trigger,
            correlation_ids=list(correlation_ids or []),
            detected_at=utc_now(),
            resolved_at=None,
            timeline=[{"event": "opened", "at": utc_now()}],
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def _transition(
        self, incident_id: str, new_status: IncidentStatus, note: str = ""
    ) -> Incident:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"unknown incident: {incident_id!r}")
        allowed = _VALID_TRANSITIONS.get(incident.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"cannot transition {incident.status!r} → {new_status!r} for {incident_id!r}"
            )
        incident.status = new_status
        entry: dict = {"event": new_status, "at": utc_now()}
        if note:
            entry["note"] = note
        incident.timeline.append(entry)
        if new_status == "resolved":
            incident.resolved_at = utc_now()
        return incident

    def escalate(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "escalated", note)

    def resolve(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "resolved", note)

    def close(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "closed", note)

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_incidents(
        self, *, status: IncidentStatus | None = None, severity: IncidentSeverity | None = None
    ) -> list[Incident]:
        results = list(self._incidents.values())
        if status is not None:
            results = [i for i in results if i.status == status]
        if severity is not None:
            results = [i for i in results if i.severity == severity]
        return results

    def apply_remediation(
        self,
        incident_id: str,
        description: str,
        *,
        action_type: str = "manual",
        outcome: str | None = None,
    ) -> RemediationAction:
        if incident_id not in self._incidents:
            raise ValueError(f"unknown incident: {incident_id!r}")
        action = RemediationAction(
            action_id=new_id("rem"),
            incident_id=incident_id,
            action_type=action_type,  # type: ignore[arg-type]
            description=description,
            executed_at=utc_now(),
            outcome=outcome,
        )
        self._remediations.append(action)
        self._incidents[incident_id].timeline.append(
            {"event": "remediation_applied", "action_id": action.action_id, "at": action.executed_at}
        )
        return action

    def scan_for_triggers(
        self, store: Any, triggers: list[IncidentTrigger]
    ) -> list[Incident]:
        """Open incidents for any trigger whose threshold is breached in the evidence store."""
        fired: list[Incident] = []
        now = datetime.now(timezone.utc)
        all_events: list[dict] = store.all()

        for trigger in triggers:
            window_start = now - timedelta(seconds=trigger.window_seconds)
            window_start_str = window_start.isoformat().replace("+00:00", "Z")
            matching = [
                e for e in all_events
                if e.get("event_type") == trigger.pattern
                and e.get("timestamp", "") >= window_start_str
            ]
            if len(matching) >= trigger.threshold:
                incident = self.open(
                    title=f"Trigger fired: {trigger.pattern} x{len(matching)} in {trigger.window_seconds}s",
                    severity="P2",
                    trigger=trigger,
                )
                fired.append(incident)

        return fired


class SQLiteIncidentManager:
    """SQLite-backed incident manager — incidents survive restarts."""

    def __init__(self, store_path: str = ".chp/incidents.sqlite") -> None:
        import sqlite3
        from pathlib import Path

        p = Path(store_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id          TEXT PRIMARY KEY,
                title                TEXT NOT NULL,
                severity             TEXT NOT NULL,
                status               TEXT NOT NULL,
                trigger_json         TEXT,
                correlation_ids_json TEXT NOT NULL DEFAULT '[]',
                detected_at          TEXT NOT NULL,
                resolved_at          TEXT,
                timeline_json        TEXT NOT NULL DEFAULT '[]'
            )
        """)
        self._conn.commit()

    def _row_to_incident(self, row: tuple) -> Incident:
        import json
        from dataclasses import asdict

        (incident_id, title, severity, status, trigger_json,
         corr_json, detected_at, resolved_at, timeline_json) = row
        trigger = None
        if trigger_json:
            td = json.loads(trigger_json)
            trigger = IncidentTrigger(
                pattern=td["pattern"],
                threshold=td["threshold"],
                window_seconds=td["window_seconds"],
            )
        return Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status=status,
            trigger=trigger,
            correlation_ids=json.loads(corr_json),
            detected_at=detected_at,
            resolved_at=resolved_at,
            timeline=json.loads(timeline_json),
        )

    def open(
        self,
        title: str,
        severity: IncidentSeverity,
        *,
        correlation_ids: list[str] | None = None,
        trigger: IncidentTrigger | None = None,
    ) -> Incident:
        import json
        from dataclasses import asdict

        incident_id = new_id("inc")
        detected_at = utc_now()
        timeline = [{"event": "opened", "at": detected_at}]
        trigger_json = json.dumps(asdict(trigger)) if trigger else None
        corr_ids = list(correlation_ids or [])
        self._conn.execute(
            """INSERT INTO incidents
               (incident_id, title, severity, status, trigger_json, correlation_ids_json,
                detected_at, resolved_at, timeline_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, title, severity, "open", trigger_json,
             json.dumps(corr_ids), detected_at, None, json.dumps(timeline)),
        )
        self._conn.commit()
        return Incident(
            incident_id=incident_id, title=title, severity=severity, status="open",
            trigger=trigger, correlation_ids=corr_ids, detected_at=detected_at,
            resolved_at=None, timeline=timeline,
        )

    def _transition(self, incident_id: str, new_status: IncidentStatus, note: str = "") -> Incident:
        import json

        row = self._conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown incident: {incident_id!r}")
        incident = self._row_to_incident(row)
        allowed = _VALID_TRANSITIONS.get(incident.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"cannot transition {incident.status!r} → {new_status!r} for {incident_id!r}"
            )
        now = utc_now()
        entry: dict = {"event": new_status, "at": now}
        if note:
            entry["note"] = note
        new_timeline = incident.timeline + [entry]
        resolved_at = now if new_status == "resolved" else incident.resolved_at
        self._conn.execute(
            """UPDATE incidents
               SET status = ?, timeline_json = ?, resolved_at = ?
               WHERE incident_id = ?""",
            (new_status, json.dumps(new_timeline), resolved_at, incident_id),
        )
        self._conn.commit()
        incident.status = new_status
        incident.timeline = new_timeline
        incident.resolved_at = resolved_at
        return incident

    def escalate(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "escalated", note)

    def resolve(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "resolved", note)

    def close(self, incident_id: str, *, note: str = "") -> Incident:
        return self._transition(incident_id, "closed", note)

    def get(self, incident_id: str) -> Incident | None:
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row) if row else None

    def list_incidents(
        self, *, status: IncidentStatus | None = None, severity: IncidentSeverity | None = None
    ) -> list[Incident]:
        clauses: list[str] = []
        params: list = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        sql = "SELECT * FROM incidents"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def apply_remediation(
        self,
        incident_id: str,
        description: str,
        *,
        action_type: str = "manual",
        outcome: str | None = None,
    ) -> RemediationAction:
        import json

        row = self._conn.execute(
            "SELECT timeline_json FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown incident: {incident_id!r}")
        action = RemediationAction(
            action_id=new_id("rem"),
            incident_id=incident_id,
            action_type=action_type,  # type: ignore[arg-type]
            description=description,
            executed_at=utc_now(),
            outcome=outcome,
        )
        timeline = json.loads(row[0])
        timeline.append({
            "event": "remediation_applied",
            "action_id": action.action_id,
            "at": action.executed_at,
        })
        self._conn.execute(
            "UPDATE incidents SET timeline_json = ? WHERE incident_id = ?",
            (json.dumps(timeline), incident_id),
        )
        self._conn.commit()
        return action

    def scan_for_triggers(
        self, store: Any, triggers: list[IncidentTrigger]
    ) -> list[Incident]:
        """Open incidents for any trigger whose threshold is breached in the evidence store."""
        fired: list[Incident] = []
        now = datetime.now(timezone.utc)
        all_events: list[dict] = store.all()

        for trigger in triggers:
            window_start = now - timedelta(seconds=trigger.window_seconds)
            window_start_str = window_start.isoformat().replace("+00:00", "Z")
            matching = [
                e for e in all_events
                if e.get("event_type") == trigger.pattern
                and e.get("timestamp", "") >= window_start_str
            ]
            if len(matching) >= trigger.threshold:
                incident = self.open(
                    title=f"Trigger fired: {trigger.pattern} x{len(matching)} in {trigger.window_seconds}s",
                    severity="P2",
                    trigger=trigger,
                )
                fired.append(incident)

        return fired

    def close_conn(self) -> None:
        self._conn.close()


def register_incident_capability(
    host: Any,
    manager: "InMemoryIncidentManager | SQLiteIncidentManager | None" = None,
) -> None:
    manager = manager or InMemoryIncidentManager()

    open_desc = CapabilityDescriptor(
        id="incident.open",
        version="1.0.0",
        description="Open a new incident with a title and severity.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident", "operations"],
        emits=list(_INCIDENT_EMITS),
    )
    escalate_desc = CapabilityDescriptor(
        id="incident.escalate",
        version="1.0.0",
        description="Escalate an open or investigating incident.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident"],
        emits=list(_INCIDENT_EMITS),
    )
    resolve_desc = CapabilityDescriptor(
        id="incident.resolve",
        version="1.0.0",
        description="Mark an incident as resolved.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident"],
        emits=list(_INCIDENT_EMITS),
    )
    close_desc = CapabilityDescriptor(
        id="incident.close",
        version="1.0.0",
        description="Close a resolved incident.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident"],
        emits=list(_INCIDENT_EMITS),
    )
    list_desc = CapabilityDescriptor(
        id="incident.list",
        version="1.0.0",
        description="List all incidents, optionally filtered by status or severity.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident"],
        emits=list(_INCIDENT_EMITS),
    )
    scan_desc = CapabilityDescriptor(
        id="incident.scan",
        version="1.0.0",
        description="Scan the evidence store for trigger threshold breaches.",
        category=CapabilityCategory.OBSERVABILITY,
        tags=["incident", "detection"],
        emits=list(_INCIDENT_EMITS),
    )

    async def _open(ctx, payload) -> dict:
        title = str(payload.get("title") or "Untitled incident")
        severity = str(payload.get("severity") or "P3")
        correlation_ids = list(payload.get("correlation_ids") or [])
        incident = manager.open(title, severity, correlation_ids=correlation_ids)  # type: ignore[arg-type]
        ctx.emit(
            "incident_opened",
            {"incident_id": incident.incident_id, "title": title, "severity": severity},
            redacted=False,
        )
        return incident.to_dict()

    async def _escalate(ctx, payload) -> dict:
        incident_id = str(payload.get("incident_id") or "")
        note = str(payload.get("note") or "")
        incident = manager.escalate(incident_id, note=note)
        ctx.emit(
            "incident_escalated",
            {"incident_id": incident_id, "note": note},
            redacted=False,
        )
        return incident.to_dict()

    async def _resolve(ctx, payload) -> dict:
        incident_id = str(payload.get("incident_id") or "")
        note = str(payload.get("note") or "")
        incident = manager.resolve(incident_id, note=note)
        ctx.emit(
            "incident_resolved",
            {"incident_id": incident_id, "note": note},
            redacted=False,
        )
        return incident.to_dict()

    async def _close(ctx, payload) -> dict:
        incident_id = str(payload.get("incident_id") or "")
        note = str(payload.get("note") or "")
        incident = manager.close(incident_id, note=note)
        ctx.emit(
            "incident_closed",
            {"incident_id": incident_id},
            redacted=False,
        )
        return incident.to_dict()

    async def _list(ctx, payload) -> dict:
        status = payload.get("status")
        severity = payload.get("severity")
        incidents = manager.list_incidents(status=status, severity=severity)  # type: ignore[arg-type]
        return {
            "incidents": [i.to_dict() for i in incidents],
            "count": len(incidents),
        }

    async def _scan(ctx, payload) -> dict:
        raw_triggers = list(payload.get("triggers") or [])
        triggers = [
            IncidentTrigger(
                pattern=str(t.get("pattern") or ""),
                threshold=int(t.get("threshold", 1)),
                window_seconds=int(t.get("window_seconds", 3600)),
            )
            for t in raw_triggers
        ]
        fired = manager.scan_for_triggers(ctx.host._store, triggers)
        for inc in fired:
            ctx.emit(
                "incident_trigger_fired",
                {"incident_id": inc.incident_id, "title": inc.title},
                redacted=False,
            )
        return {"fired": [i.to_dict() for i in fired], "count": len(fired)}

    host.register(open_desc, _open)
    host.register(escalate_desc, _escalate)
    host.register(resolve_desc, _resolve)
    host.register(close_desc, _close)
    host.register(list_desc, _list)
    host.register(scan_desc, _scan)
