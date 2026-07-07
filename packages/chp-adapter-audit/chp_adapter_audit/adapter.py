"""AuditAdapter — queryable governance audit log over the CHP evidence store.

Three capabilities:

* ``query_invocations`` — filter by capability_id, outcome, time window, limit;
  returns per-invocation summaries (never raw event payloads).
* ``get_invocation`` — fetch all events for one invocation_id; returns only
  metadata (event_type, timestamp, outcome) to avoid leaking sensitive payloads
  that may have been stored by other adapters.
* ``stats`` — aggregate counts by outcome and by capability over a time window.

Evidence hygiene: only counts, IDs, event_types, and timestamps are stored or
returned. The stored event payloads (which may carry PII, tokens, or secrets
from other adapters) are NEVER included in audit evidence or return values.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = ["audit_query", "audit_result", "audit_error"]


@dataclass
class AuditConfig:
    """Config for AuditAdapter.

    ``max_results`` caps the maximum rows returned by any query.
    ``store`` is injectable for tests (bypasses host.store binding).
    """

    max_results: int = 1000
    store: Any = None


class AuditAdapter(BaseAdapter):
    """Static adapter exposing the host's evidence store as governed capabilities."""

    adapter_id = "chp.adapters.audit"
    adapter_name = "Audit Log"
    adapter_description = "Query the CHP evidence store with filters and aggregate stats."
    adapter_category = "governance"
    adapter_tags = ["audit", "governance", "evidence", "meta"]

    def __init__(self, config: AuditConfig | None = None) -> None:
        self._config = config or AuditConfig()
        self._store: Any = self._config.store  # None until on_register if not injected

    def on_register(self, host: Any) -> None:
        if self._store is None:
            self._store = host.store
        self._host = host  # for emission_report's declared-emits catalog (host.discover)

    # ------------------------------------------------------------------
    # query_invocations
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.query_invocations",
        version="1.0.0",
        description="Query invocation records from the audit log with optional filters.",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "capability_id": {"type": "string", "description": "Filter by exact capability ID."},
                "outcome": {
                    "type": "string",
                    "enum": ["success", "failure", "denied", "skipped"],
                    "description": "Filter by invocation outcome.",
                },
                "since": {"type": "string", "description": "ISO-8601 lower bound (inclusive)."},
                "until": {"type": "string", "description": "ISO-8601 upper bound (inclusive)."},
                "limit": {"type": "integer", "minimum": 1, "default": 100},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance"],
    )
    async def query_invocations(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound — register with a host first")

        limit = min(payload.get("limit") or 100, self._config.max_results)
        cap_id = payload.get("capability_id")
        outcome = payload.get("outcome")
        since = payload.get("since")
        until = payload.get("until")

        ctx.emit("audit_query", {
            "op": "query_invocations",
            "filters": {k: v for k, v in {
                "capability_id": cap_id, "outcome": outcome, "since": since, "until": until,
            }.items() if v is not None},
            "limit": limit,
        }, redacted=False)

        events = self._store.query(
            capability_id=cap_id,
            outcome=outcome,
            since=since,
            until=until,
            limit=limit * 10,  # over-fetch to group by invocation
        )

        # Exclude the current audit invocation so it doesn't appear in results
        current_inv_id = ctx.envelope.invocation_id
        events = [e for e in events if e.get("invocation_id") != current_inv_id]

        invocations = _group_by_invocation(events, limit)

        ctx.emit("audit_result", {
            "op": "query_invocations",
            "total": len(invocations),
        }, redacted=False)

        return {"invocations": invocations, "total": len(invocations)}

    # ------------------------------------------------------------------
    # get_invocation
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.get_invocation",
        version="1.0.0",
        description="Fetch event metadata for a specific invocation ID.",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "invocation_id": {"type": "string"},
            },
            "required": ["invocation_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance"],
    )
    async def get_invocation(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound")

        invocation_id = payload["invocation_id"]

        ctx.emit("audit_query", {
            "op": "get_invocation",
            "invocation_id": invocation_id,
        }, redacted=False)

        events = self._store.by_invocation(invocation_id)

        if not events:
            ctx.emit("audit_error", {
                "reason": "not_found", "invocation_id": invocation_id,
            }, redacted=False)
            raise ValueError(f"Invocation not found: {invocation_id!r}")

        # Strip payloads — only metadata (event_type, timestamp, outcome) returned
        stripped = [
            {
                "event_id": e.get("event_id"),
                "event_type": e.get("event_type"),
                "timestamp": e.get("timestamp"),
                "outcome": e.get("outcome"),
                "sequence": e.get("sequence"),
            }
            for e in events
        ]

        ctx.emit("audit_result", {
            "op": "get_invocation",
            "invocation_id": invocation_id,
            "event_count": len(stripped),
        }, redacted=False)

        return {
            "invocation_id": invocation_id,
            "correlation_id": (events[0].get("correlation") or {}).get("correlation_id"),
            "events": stripped,
            "event_count": len(stripped),
        }

    # ------------------------------------------------------------------
    # token_report
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.token_report",
        version="1.0.0",
        description=(
            "Aggregate sovereign inference token usage by model. Returns per-model "
            "token totals, call counts, backfill summary (calls before token tracking "
            "was added on 2026-06-17), and estimated frontier-equivalent cost."
        ),
        category="observability",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO-8601 lower bound."},
                "until": {"type": "string", "description": "ISO-8601 upper bound."},
                "frontier_price_per_1m_input": {
                    "type": "number",
                    "description": "Frontier input token price per 1M tokens (default 3.0, Claude Sonnet rate).",
                },
                "frontier_price_per_1m_output": {
                    "type": "number",
                    "description": "Frontier output token price per 1M tokens (default 15.0, Claude Sonnet rate).",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance", "tokens", "observability"],
    )
    async def token_report(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound")

        since = payload.get("since")
        until = payload.get("until")
        input_price = float(payload.get("frontier_price_per_1m_input") or 3.0)
        output_price = float(payload.get("frontier_price_per_1m_output") or 15.0)

        ctx.emit("audit_query", {"op": "token_report", "since": since, "until": until}, redacted=False)

        events = self._store.query(
            capability_id="chp.adapters.http.request",
            since=since,
            until=until,
        )
        http_responses = [e for e in events if e.get("event_type") == "http_response"]

        with_tokens = [e for e in http_responses if "prompt_tokens" in e.get("payload", {})]
        without_tokens = [e for e in http_responses if "prompt_tokens" not in e.get("payload", {})]

        by_model: dict[str, dict] = {}
        for e in with_tokens:
            p = e["payload"]
            m = p.get("model", "unknown")
            rec = by_model.setdefault(m, {"model": m, "prompt_tokens": 0, "completion_tokens": 0, "calls": 0})
            rec["prompt_tokens"] += p.get("prompt_tokens", 0)
            rec["completion_tokens"] += p.get("completion_tokens", 0)
            rec["calls"] += 1

        total_prompt = sum(r["prompt_tokens"] for r in by_model.values())
        total_completion = sum(r["completion_tokens"] for r in by_model.values())
        frontier_cost = (
            total_prompt / 1_000_000 * input_price
            + total_completion / 1_000_000 * output_price
        )

        earliest_tracked = min(
            (e["timestamp"] for e in with_tokens if e.get("timestamp")), default=None
        )

        result = {
            "window": {"since": since, "until": until},
            "sovereign": {
                "total_prompt_tokens": total_prompt,
                "total_completion_tokens": total_completion,
                "total_tokens": total_prompt + total_completion,
                "by_model": sorted(by_model.values(), key=lambda r: -r["calls"]),
            },
            "backfill": {
                "calls_without_token_data": len(without_tokens),
                "note": "Calls before token tracking (2026-06-17). Counts only, no token data.",
                "earliest_tracked": earliest_tracked,
            },
            "estimated_frontier_cost_usd": round(frontier_cost, 4),
            "pricing_basis": f"${input_price}/1M input, ${output_price}/1M output (Claude Sonnet rates)",
        }

        ctx.emit("audit_result", {
            "op": "token_report",
            "total_tokens": total_prompt + total_completion,
            "models": list(by_model.keys()),
        }, redacted=False)
        return result

    # ------------------------------------------------------------------
    # stats
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.stats",
        version="1.0.0",
        description="Aggregate invocation counts by outcome and capability over a time window.",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO-8601 lower bound."},
                "until": {"type": "string", "description": "ISO-8601 upper bound."},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance"],
    )
    async def stats(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound")

        since = payload.get("since")
        until = payload.get("until")

        ctx.emit("audit_query", {
            "op": "stats",
            "since": since,
            "until": until,
        }, redacted=False)

        events = self._store.query(since=since, until=until)

        # Exclude the current audit invocation
        current_inv_id = ctx.envelope.invocation_id
        events = [e for e in events if e.get("invocation_id") != current_inv_id]

        # Count DISTINCT invocations (robust to a capability that double-emits
        # execution_started alongside the host — keying by invocation_id
        # collapses the duplicate).
        started_by_inv: dict[str, dict] = {}
        for e in events:
            if e.get("event_type") == "execution_started":
                inv = e.get("invocation_id")
                if inv is not None:
                    started_by_inv.setdefault(inv, e)
        total = len(started_by_inv)

        # Outcome lives on the TERMINAL event, not on execution_started (which is
        # always outcome=None). Map invocation_id → terminal outcome, preferring
        # a real outcome over unknown when duplicates exist. An invocation with
        # no terminal event is "incomplete" (not "unknown").
        _TERMINAL = {"execution_completed", "execution_failed",
                     "execution_denied", "execution_skipped"}
        terminal_outcome: dict[str, str] = {}
        for e in events:
            if e.get("event_type") in _TERMINAL:
                inv = e.get("invocation_id")
                if inv is None:
                    continue
                out = e.get("outcome") or "unknown"
                # Don't let a duplicate outcome-less terminal clobber a real one.
                if inv not in terminal_outcome or terminal_outcome[inv] == "unknown":
                    terminal_outcome[inv] = out

        by_outcome: dict[str, int] = defaultdict(int)
        by_cap: dict[str, int] = defaultdict(int)
        for inv, e in started_by_inv.items():
            by_outcome[terminal_outcome.get(inv, "incomplete")] += 1
            cap = e.get("capability_id") or "unknown"
            by_cap[cap] += 1

        error_rate = (by_outcome.get("failure", 0) / total) if total > 0 else 0.0
        by_capability = sorted(
            [{"id": k, "count": v} for k, v in by_cap.items()],
            key=lambda x: x["count"],
            reverse=True,
        )

        ctx.emit("audit_result", {
            "op": "stats",
            "total_invocations": total,
        }, redacted=False)

        return {
            "total_invocations": total,
            "by_outcome": dict(by_outcome),
            "by_capability": by_capability,
            "error_rate": round(error_rate, 4),
        }

    # ------------------------------------------------------------------
    # emission_report — review evidence-emission coverage per capability
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.emission_report",
        version="1.0.0",
        description=(
            "Review the protocol's evidence emission: join each capability's DECLARED emits "
            "(from the host catalog) against the event types actually OBSERVED in the audit "
            "log. Flags `no_declared_emits` (capability claims no evidence — a gap), "
            "`declared_unobserved` (invoked but emitted none of its declared events), and "
            "`undeclared_observed` (emitted an event type it never declared — drift). Builds "
            "confidence in the chain and surfaces protocol issues. Metadata only."
        ),
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO-8601 lower bound for observed events."},
                "until": {"type": "string", "description": "ISO-8601 upper bound."},
                "flagged_only": {"type": "boolean", "default": True,
                                 "description": "Return only capabilities with a flag (vs the full catalog)."},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance", "evidence-quality"],
    )
    async def emission_report(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound")
        ctx.emit("audit_query", {"op": "emission_report"}, redacted=False)

        # Framework lifecycle events are auto-emitted (not adapter-declared) — exclude them
        # so "observed adapter evidence" is compared fairly against declared emits.
        lifecycle = {"execution_started", "execution_completed", "execution_failed",
                     "execution_denied", "capability_invoked"}

        # Declared emits per capability, from the host catalog.
        declared: dict[str, set] = {}
        try:
            for c in (self._host.discover() or {}).get("capabilities", []):
                cid = c.get("id")
                if cid:
                    declared[cid] = set(c.get("emits") or [])
        except Exception as exc:  # noqa: BLE001
            ctx.emit("audit_error", {"reason": f"catalog_unavailable:{str(exc)[:80]}"}, redacted=False)

        # Observed event types per capability, from the audit store.
        observed: dict[str, set] = defaultdict(set)
        for e in self._store.query(since=payload.get("since"), until=payload.get("until")):
            cid, et = e.get("capability_id"), e.get("event_type")
            if cid and et and et not in lifecycle:
                observed[cid].add(et)

        # Framework sentinels (e.g. chp.core.conversation.turn — a conversation-turn marker, not a
        # declarable adapter @capability) are not audited for emit-declaration drift.
        for d in (declared, observed):
            for k in [k for k in d if k.startswith("chp.core.")]:
                d.pop(k, None)

        rows = []
        for cid in sorted(set(declared) | set(observed)):
            dec, obs = declared.get(cid, set()), observed.get(cid, set())
            invoked = cid in observed
            flags = []
            if not dec:
                flags.append("no_declared_emits")
            if invoked and dec and not (dec & obs):
                flags.append("declared_unobserved")
            if obs - dec:
                flags.append("undeclared_observed")
            if flags or not payload.get("flagged_only", True):
                rows.append({"capability_id": cid, "declared": sorted(dec), "observed": sorted(obs),
                             "invoked": invoked, "flags": flags})

        total = len(set(declared) | set(observed))
        invoked_caps = [c for c in declared if c in observed] + [c for c in observed if c not in declared]
        clean_invoked = sum(1 for c in set(invoked_caps) if (declared.get(c) and (declared[c] & observed.get(c, set()))))
        n_invoked = len(set(invoked_caps))
        summary = {
            "total_capabilities": total,
            "no_declared_emits": sum(1 for c in declared if not declared[c]),
            "invoked_capabilities": n_invoked,
            "emission_score": round(clean_invoked / n_invoked, 4) if n_invoked else None,
            "flagged": len(rows) if payload.get("flagged_only", True) else sum(1 for r in rows if r["flags"]),
        }
        ctx.emit("audit_result", {"op": "emission_report", **summary}, redacted=False)
        return {"summary": summary, "capabilities": rows}

    @capability(
        id="chp.adapters.audit.agent_runs",
        version="1.0.0",
        description="List recent agent_run trace spans (steward/dreamer runs) from the evidence chain: "
                    "agent, duration, outcome, and for model agents the model, call count, tokens, and "
                    "tools used. CHP's native, langfuse-shaped agent observability. Read-only; the spans "
                    "are redacted by construction (counts/ids/tool-names, never prompt text).",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "agent": {"type": "string", "description": "filter by agent, e.g. 'steward:grow'"},
                "limit": {"type": "integer", "description": "max spans (most recent first)"},
                "since": {"type": "string"}, "until": {"type": "string"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
    )
    async def agent_runs(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            return {"error": "evidence store not bound", "agent_runs": []}
        limit = min(payload.get("limit") or 50, self._config.max_results)
        want = payload.get("agent")
        spans = []
        for e in self._store.query(capability_id="chp.adapters.stewards.record_run",
                                   since=payload.get("since"), until=payload.get("until")):
            if e.get("event_type") != "agent_run":
                continue
            p = e.get("payload") or {}
            if want and p.get("agent") != want:
                continue
            span = {k: p.get(k) for k in ("agent", "trace_id", "duration_ms", "outcome", "model",
                    "model_calls", "prompt_tokens", "completion_tokens", "findings", "filed")}
            span["tools_called"] = p.get("tools_called") or []
            span["at"] = e.get("timestamp")
            spans.append(span)
        spans = spans[-limit:][::-1]  # most recent first
        total_tokens = sum((s.get("prompt_tokens") or 0) + (s.get("completion_tokens") or 0) for s in spans)
        ctx.emit("audit_result", {"op": "agent_runs", "count": len(spans), "total_tokens": total_tokens},
                 redacted=False)
        return {"agent_runs": spans, "count": len(spans), "total_tokens": total_tokens}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _group_by_invocation(events: list[dict], limit: int) -> list[dict]:
    """Group a flat event list into per-invocation summaries, capped at ``limit``."""
    seen: dict[str, dict] = {}
    for e in events:
        inv_id = e.get("invocation_id")
        if inv_id is None:
            continue
        if inv_id not in seen:
            if len(seen) >= limit:
                continue
            seen[inv_id] = {
                "invocation_id": inv_id,
                "capability_id": e.get("capability_id"),
                "correlation_id": (e.get("correlation") or {}).get("correlation_id"),
                "started_at": e.get("timestamp"),
                "outcome": None,
                "event_count": 0,
            }
        seen[inv_id]["event_count"] += 1
        # Capture outcome from terminal lifecycle event
        if e.get("event_type") in ("execution_completed", "execution_failed", "execution_denied"):
            seen[inv_id]["outcome"] = e.get("outcome")
        if e.get("timestamp"):
            seen[inv_id]["completed_at"] = e.get("timestamp")

    return list(seen.values())
