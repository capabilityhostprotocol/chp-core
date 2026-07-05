"""Evidence lifecycle compliance management for CHP §8.5."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .types import (
    CapabilityCategory,
    CapabilityDescriptor,
    ComplianceReport,
    RetentionPolicy,
    new_id,
    utc_now,
)

_COMPLIANCE_EMITS = [
    "execution_started",
    "execution_completed",
    "execution_failed",
    "retention_policy_applied",
    "evidence_purged",
    "evidence_redacted",
    "compliance_report_generated",
]


class SQLiteComplianceManager:
    """Applies retention policies directly to a SQLiteEvidenceStore's database."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def apply_retention(self, policies: list[RetentionPolicy]) -> ComplianceReport:
        total_purged = 0
        total_redacted = 0
        total_inspected = 0

        with self._store._lock:
            row = self._store._conn.execute(
                "SELECT COUNT(*) AS count FROM evidence_events"
            ).fetchone()
            total_inspected = int(row["count"])

            for policy in policies:
                for pattern in policy.applies_to:
                    if policy.retain_days >= 0:
                        cutoff = datetime.now(timezone.utc) - timedelta(days=policy.retain_days)
                        cutoff_str = cutoff.isoformat().replace("+00:00", "Z")

                        # Prune WHOLE correlations whose newest event is past the
                        # cutoff — never individual events, which would leave a
                        # survivor's prev_hash pointing at a deleted row and break
                        # verify_chain. A fully-removed correlation can't split a
                        # chain. (ponytail: whole-correlation granularity; add a
                        # checkpoint table only if partial pruning is ever needed.)
                        if pattern == "*":
                            sql = (
                                "DELETE FROM evidence_events WHERE correlation_id IN ("
                                "  SELECT correlation_id FROM evidence_events "
                                "  GROUP BY correlation_id HAVING MAX(timestamp) < ?)"
                            )
                            params: list = [cutoff_str]
                        else:
                            sql = (
                                "DELETE FROM evidence_events WHERE correlation_id IN ("
                                "  SELECT correlation_id FROM evidence_events "
                                "  GROUP BY correlation_id "
                                "  HAVING MAX(timestamp) < ? AND SUM(capability_id GLOB ?) > 0)"
                            )
                            params = [cutoff_str, pattern]
                        cursor = self._store._conn.execute(sql, params)
                        total_purged += cursor.rowcount

                    if policy.redact_payload_after_days is not None:
                        redact_cutoff = (
                            datetime.now(timezone.utc)
                            - timedelta(days=policy.redact_payload_after_days)
                        )
                        redact_str = redact_cutoff.isoformat().replace("+00:00", "Z")
                        # Redaction rewrites the payload, so the stored content_hash
                        # no longer matches — NULL it (event becomes honestly
                        # `unverified` in verify_chain) rather than leaving a hash
                        # that fails as if tampered.
                        if pattern == "*":
                            sql = (
                                "UPDATE evidence_events "
                                "SET payload_json = '{}', "
                                "event_json = json_set(event_json, '$.payload', json('{}')), "
                                "content_hash = NULL "
                                "WHERE timestamp < ? AND payload_json != '{}'"
                            )
                            params = [redact_str]
                        else:
                            sql = (
                                "UPDATE evidence_events "
                                "SET payload_json = '{}', "
                                "event_json = json_set(event_json, '$.payload', json('{}')), "
                                "content_hash = NULL "
                                "WHERE timestamp < ? AND capability_id GLOB ? "
                                "AND payload_json != '{}'"
                            )
                            params = [redact_str, pattern]
                        cursor = self._store._conn.execute(sql, params)
                        total_redacted += cursor.rowcount

            self._store._conn.commit()

        return ComplianceReport(
            report_id=new_id("cr"),
            policy_ids=[p.policy_id for p in policies],
            store_path=self._store.path,
            events_inspected=total_inspected,
            events_purged=total_purged,
            events_redacted=total_redacted,
            generated_at=utc_now(),
        )

    def generate_report(self) -> ComplianceReport:
        with self._store._lock:
            row = self._store._conn.execute(
                "SELECT COUNT(*) AS count FROM evidence_events"
            ).fetchone()
            count = int(row["count"])
        return ComplianceReport(
            report_id=new_id("cr"),
            policy_ids=[],
            store_path=self._store.path,
            events_inspected=count,
            events_purged=0,
            events_redacted=0,
            generated_at=utc_now(),
        )

    def purge(self, capability_id_pattern: str, before_ts: str) -> int:
        with self._store._lock:
            if capability_id_pattern == "*":
                cursor = self._store._conn.execute(
                    "DELETE FROM evidence_events WHERE timestamp < ?",
                    (before_ts,),
                )
            else:
                cursor = self._store._conn.execute(
                    "DELETE FROM evidence_events WHERE timestamp < ? AND capability_id GLOB ?",
                    (before_ts, capability_id_pattern),
                )
            self._store._conn.commit()
        return cursor.rowcount


def register_compliance_capability(
    host: Any,
    manager: SQLiteComplianceManager,
) -> None:
    report_desc = CapabilityDescriptor(
        id="compliance.report",
        version="1.0.0",
        description="Generate a compliance report showing current evidence store state.",
        category=CapabilityCategory.GOVERNANCE,
        tags=["compliance", "observability"],
        emits=list(_COMPLIANCE_EMITS),
    )

    apply_desc = CapabilityDescriptor(
        id="compliance.apply_retention",
        version="1.0.0",
        description="Apply retention policies to purge or redact old evidence records.",
        category=CapabilityCategory.GOVERNANCE,
        tags=["compliance", "retention"],
        emits=list(_COMPLIANCE_EMITS),
    )

    purge_desc = CapabilityDescriptor(
        id="compliance.purge",
        version="1.0.0",
        description="Explicitly purge evidence records matching a capability pattern before a timestamp.",
        category=CapabilityCategory.GOVERNANCE,
        tags=["compliance", "purge"],
        emits=list(_COMPLIANCE_EMITS),
    )

    async def _report(ctx, payload) -> dict:
        report = manager.generate_report()
        ctx.emit(
            "compliance_report_generated",
            {
                "events_inspected": report.events_inspected,
                "store_path": report.store_path,
            },
            redacted=False,
        )
        return report.to_dict()

    async def _apply_retention(ctx, payload) -> dict:
        raw_policies = list(payload.get("policies") or [])
        policies = [
            RetentionPolicy(
                policy_id=str(p.get("policy_id") or new_id("pol")),
                retain_days=int(p.get("retain_days", -1)),
                applies_to=list(p.get("applies_to") or ["*"]),
                redact_payload_after_days=(
                    int(p["redact_payload_after_days"])
                    if p.get("redact_payload_after_days") is not None
                    else None
                ),
            )
            for p in raw_policies
        ]
        report = manager.apply_retention(policies)
        ctx.emit(
            "retention_policy_applied",
            {
                "policy_ids": report.policy_ids,
                "events_purged": report.events_purged,
                "events_redacted": report.events_redacted,
            },
            redacted=False,
        )
        ctx.emit(
            "compliance_report_generated",
            {"events_inspected": report.events_inspected, "store_path": report.store_path},
            redacted=False,
        )
        return report.to_dict()

    async def _purge(ctx, payload) -> dict:
        pattern = str(payload.get("capability_id_pattern") or "*")
        before_ts = str(payload.get("before_ts") or utc_now())
        count = manager.purge(pattern, before_ts)
        ctx.emit("evidence_purged", {"count": count, "pattern": pattern}, redacted=False)
        return {"purged": count, "pattern": pattern}

    host.register(report_desc, _report)
    host.register(apply_desc, _apply_retention)
    host.register(purge_desc, _purge)
