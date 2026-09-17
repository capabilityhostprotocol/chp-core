"""AuditAdapter — queryable governance audit log over the CHP evidence store.

Capabilities:

* ``query_invocations`` — filter by capability_id, outcome, time window, limit;
  returns per-invocation summaries (never raw event payloads).
* ``get_invocation`` — fetch all events for one invocation_id; returns only
  metadata (event_type, timestamp, outcome) to avoid leaking sensitive payloads
  that may have been stored by other adapters.
* ``stats`` — aggregate counts by outcome and by capability over a time window.
* ``inclusion_proof`` — a verifiable Merkle store-head inclusion proof
  (chp-store-head-v2, RFC 6962) that a correlation's evidence is committed under
  the host's current evidence store head. A self-contained, third-party-verifiable
  artifact (verify with chp-sdk ``verifyStoreHeadInclusion``); metadata only.

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
                "correlation_id": {"type": "string", "description": "Filter to one run/correlation (indexed — the reliable way to fetch a run's steps)."},
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
        correlation_id = payload.get("correlation_id")
        outcome = payload.get("outcome")
        since = payload.get("since")
        until = payload.get("until")

        ctx.emit("audit_query", {
            "op": "query_invocations",
            "filters": {k: v for k, v in {
                "capability_id": cap_id, "correlation_id": correlation_id,
                "outcome": outcome, "since": since, "until": until,
            }.items() if v is not None},
            "limit": limit,
        }, redacted=False)

        events = self._store.query(
            capability_id=cap_id,
            correlation_id=correlation_id,
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
    # inclusion_proof — verifiable Merkle store-head inclusion (the "provable" dimension)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.inclusion_proof",
        version="1.0.0",
        description="A verifiable Merkle store-head inclusion proof (chp-store-head-v2, RFC 6962) that a "
                    "given correlation's evidence is committed under the host's CURRENT evidence store head. "
                    "Returns the store-head root, the inclusion proof, and a metadata-only event summary — a "
                    "self-contained, third-party-verifiable artifact (verify with chp-sdk "
                    "verifyStoreHeadInclusion). This is the governed twin of the /head/inclusion HTTP endpoint "
                    "(no auth wall), so a host can publish proof that a real governed action is committed. "
                    "Metadata only: ids, hashes, outcomes, timestamps — never event payloads.",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "correlation_id": {"type": "string",
                                   "description": "The run/correlation to prove is committed in the store head."},
            },
            "required": ["correlation_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["audit", "governance", "evidence", "provable"],
    )
    async def inclusion_proof(self, ctx: Any, payload: dict) -> dict:
        if self._store is None:
            ctx.emit("audit_error", {"reason": "store_not_bound"}, redacted=False)
            raise RuntimeError("AuditAdapter: store not bound — register with a host first")
        if not hasattr(self._store, "get_store_head"):
            ctx.emit("audit_error", {"reason": "store_head_unsupported"}, redacted=False)
            raise RuntimeError("AuditAdapter: evidence store does not support Merkle store heads")

        from chp_core.merkle import CHP_STORE_HEAD_V2, store_head_inclusion_proof

        corr = str(payload["correlation_id"]).strip()
        ctx.emit("audit_query", {"op": "inclusion_proof", "correlation_id": corr}, redacted=False)

        head = self._store.get_store_head(fresh=True, scheme=CHP_STORE_HEAD_V2)
        if corr not in head["leaves"]:
            ctx.emit("audit_error", {"reason": "correlation_not_committed", "correlation_id": corr}, redacted=False)
            raise RuntimeError(f"correlation {corr!r} is not committed in the current store head")

        proof = store_head_inclusion_proof(head["leaves"], corr)

        # Metadata-only summary of the proven correlation (ids/caps/outcomes/counts — never payloads).
        events = self._store.query(correlation_id=corr, limit=self._config.max_results)
        cap_ids = sorted({e.get("capability_id") for e in events if e.get("capability_id")})
        outcomes = sorted({e.get("outcome") for e in events if e.get("outcome")})
        host_id = getattr(self._host, "host_id", getattr(self._host, "_host_id", "unknown"))

        # v2 authenticity: self-sign the head with the host's ed25519 identity key when it holds one,
        # binding the PUBLISHED head to the host (non-repudiable) — so a verifier checks authenticity, not
        # just inclusion. Graceful: a host at the hash-chain tier (no key) omits head_signature and the proof
        # stays inclusion-verifiable. Signed bytes = store_head_anchor_message canonical form (json sort_keys).
        head_signature = None
        try:
            import base64 as _b64mod

            from chp_core import signing
            from chp_core.types import utc_now
            host_key = signing.load_host_key(signing.resolve_key_dir(host_id))
            if host_key is not None and host_key.can_sign:
                anchored_at = utc_now()
                message = signing.store_head_anchor_message(
                    host_id, head["sequence"], head["store_head"], anchored_at)
                head_signature = {
                    "algorithm": "ed25519",
                    "message_scheme": "store-head-anchor",
                    "anchored_at": anchored_at,
                    "public_key_b64": host_key.public_key_b64,
                    "key_id": host_key.key_id,
                    "signature_b64": _b64mod.b64encode(host_key._private.sign(message)).decode(),
                }
        except Exception as exc:  # signing is best-effort; never fail the proof over it
            ctx.emit("audit_error", {"reason": "head_sign_skipped", "detail": type(exc).__name__}, redacted=False)

        ctx.emit("audit_result", {"op": "inclusion_proof", "correlation_id": corr,
                                  "sequence": head["sequence"], "tree_size": proof["tree_size"],
                                  "signed": head_signature is not None}, redacted=False)
        return {
            "scheme": CHP_STORE_HEAD_V2,
            "host_id": host_id,
            "sequence": head["sequence"],
            "store_head": head["store_head"],
            "inclusion": proof,
            "event_summary": {
                "correlation_id": corr,
                "capability_ids": cap_ids,
                "outcomes": outcomes,
                "event_count": len(events),
            },
            **({"head_signature": head_signature} if head_signature else {}),
            "verify_with": "chp-sdk verifyStoreHeadInclusion + ed25519 over store_head_anchor_message(host_id, sequence, store_head, head_signature.anchored_at)",
        }

    # ------------------------------------------------------------------
    # countersign_head — external witness (provable v3 independence)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.audit.countersign_head",
        version="1.0.0",
        description="WITNESS another host's store head: sign {host_id, sequence, store_head} with THIS host's "
                    "ed25519 identity key (an independent countersignature over store_head_anchor_message). Run "
                    "on a DIFFERENT node than the head's own host to attest, independently, that it saw that "
                    "head — the external-independence tier of provable evidence, so a verifier need not trust "
                    "the head's own host. Returns a witness statement; omitted if this host holds no signing key.",
        category="governance",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "host_id": {"type": "string", "minLength": 1, "description": "the head's own host id"},
                "sequence": {"type": "integer", "minimum": 0},
                "store_head": {"type": "string", "minLength": 1, "description": "the merkle store-head root (hex)"},
                "anchored_at": {"type": "string", "description": "ISO-8601 timestamp; defaults to now"},
            },
            "required": ["host_id", "sequence", "store_head"],
            "additionalProperties": False,
        },
        emits=["audit_head_countersigned"],
        tags=["audit", "governance", "evidence", "provable", "witness"],
    )
    async def countersign_head(self, ctx: Any, payload: dict) -> dict:
        import base64 as _b64mod

        from chp_core import signing
        from chp_core.types import utc_now

        host_id = str(payload["host_id"]).strip()
        sequence = int(payload["sequence"])
        store_head = str(payload["store_head"]).strip()
        anchored_at = str(payload.get("anchored_at") or utc_now())

        # THIS (the witness) host's own key — resolve by the witness's host id so the per-host key dir
        # (~/.chp/keys/<host_id>) is found, not only $CHP_KEY_DIR (matches inclusion_proof).
        witness_host = getattr(self._host, "host_id", getattr(self._host, "_host_id", "unknown"))
        host_key = signing.load_host_key(signing.resolve_key_dir(witness_host))
        if host_key is None or not host_key.can_sign:
            ctx.emit("audit_head_countersigned", {"host_id": host_id, "sequence": sequence, "witnessed": False},
                     redacted=False)
            return {"witnessed": False, "reason": "no-signing-key"}

        message = signing.store_head_anchor_message(host_id, sequence, store_head, anchored_at)
        witness = {
            "witness_host_id": witness_host,
            "algorithm": "ed25519",
            "anchored_at": anchored_at,
            "public_key_b64": host_key.public_key_b64,
            "key_id": host_key.key_id,
            "signature_b64": _b64mod.b64encode(host_key._private.sign(message)).decode(),
            "head": {"host_id": host_id, "sequence": sequence, "store_head": store_head},
        }
        ctx.emit("audit_head_countersigned",
                 {"host_id": host_id, "sequence": sequence, "witness_key_id": host_key.key_id, "witnessed": True},
                 redacted=False)
        return {"witnessed": True, "witness": witness}

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

        # A scalar-column projection (event_type/invocation_id/capability_id/
        # outcome) — NOT full events. stats only aggregates these four fields, so
        # parsing every event_json (the old query()) was pure waste: the ~30s
        # cold-scan on a large store. Same keys, same aggregation below.
        events = self._store.stats_projection(since=since, until=until)

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
