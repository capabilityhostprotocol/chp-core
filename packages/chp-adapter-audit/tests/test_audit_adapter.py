"""Tests for chp_adapter_audit.adapter."""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_audit import AuditAdapter, AuditConfig


# --------------------------------------------------------------------------
# Minimal echo adapter to generate invocation evidence
# --------------------------------------------------------------------------

class _EchoAdapter:
    adapter_id = "chp.adapters.echo"

    @capability(
        id="chp.adapters.echo.ping",
        version="1.0.0",
        description="Echo.",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {"msg": {"type": "string"}},
            "additionalProperties": False,
        },
    )
    async def ping(self, ctx, payload):
        return {"pong": payload.get("msg", "")}

    @capability(
        id="chp.adapters.echo.fail",
        version="1.0.0",
        description="Always fails.",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def fail(self, ctx, payload):
        raise RuntimeError("forced failure")

    def capabilities(self):
        from chp_core.adapters import HostedCapability
        from chp_core.decorators import adapt_callable, get_capability_descriptor
        import inspect
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            desc = get_capability_descriptor(method.__func__)
            if desc is not None:
                yield HostedCapability(descriptor=desc, handler=adapt_callable(method))


def _make_host():
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, _EchoAdapter())
    register_adapter(host, AuditAdapter())
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. Shaping
# --------------------------------------------------------------------------

class TestShaping:
    def test_capability_ids(self):
        host = _make_host()
        ids = {c.descriptor.id for c in AuditAdapter().capabilities()}
        assert ids == {
            "chp.adapters.audit.query_invocations",
            "chp.adapters.audit.get_invocation",
            "chp.adapters.audit.stats",
            "chp.adapters.audit.token_report",
        }

    def test_all_risk_low(self):
        for cap in AuditAdapter().capabilities():
            assert cap.descriptor.risk == "low"


# --------------------------------------------------------------------------
# 2. query_invocations
# --------------------------------------------------------------------------

class TestQueryInvocations:
    def test_empty_store(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.query_invocations", {})
        assert r.outcome == "success"
        assert r.data["total"] == 0
        assert r.data["invocations"] == []

    def test_returns_after_invocations(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        host.invoke("chp.adapters.echo.ping", {"msg": "b"})
        r = host.invoke("chp.adapters.audit.query_invocations", {})
        assert r.data["total"] == 2

    def test_filter_by_capability_id(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        host.invoke("chp.adapters.echo.fail", {})
        r = host.invoke("chp.adapters.audit.query_invocations",
                        {"capability_id": "chp.adapters.echo.ping"})
        assert r.data["total"] == 1
        assert r.data["invocations"][0]["capability_id"] == "chp.adapters.echo.ping"

    def test_filter_by_outcome(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        host.invoke("chp.adapters.echo.fail", {})
        r = host.invoke("chp.adapters.audit.query_invocations", {"outcome": "success"})
        # Only ping should appear
        assert all(inv["outcome"] in ("success", None) for inv in r.data["invocations"])

    def test_invocation_summary_keys(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        r = host.invoke("chp.adapters.audit.query_invocations", {})
        inv = r.data["invocations"][0]
        assert "invocation_id" in inv
        assert "capability_id" in inv
        assert "event_count" in inv

    def test_payloads_never_in_invocation_summary(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "super_secret_value"})
        r = host.invoke("chp.adapters.audit.query_invocations", {})
        dump = str(r.data["invocations"])
        assert "super_secret_value" not in dump

    def test_extra_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.query_invocations", {"injected": "bad"})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 3. get_invocation
# --------------------------------------------------------------------------

class TestGetInvocation:
    def test_returns_event_metadata(self):
        host = _make_host()
        result = host.invoke("chp.adapters.echo.ping", {"msg": "test"})
        inv_id = result.invocation_id

        r = host.invoke("chp.adapters.audit.get_invocation", {"invocation_id": inv_id})
        assert r.outcome == "success"
        assert r.data["invocation_id"] == inv_id
        assert r.data["event_count"] > 0

    def test_events_have_type_and_timestamp(self):
        host = _make_host()
        result = host.invoke("chp.adapters.echo.ping", {"msg": "test"})
        r = host.invoke("chp.adapters.audit.get_invocation",
                        {"invocation_id": result.invocation_id})
        evt = r.data["events"][0]
        assert "event_type" in evt
        assert "timestamp" in evt

    def test_payloads_stripped_from_events(self):
        host = _make_host()
        result = host.invoke("chp.adapters.echo.ping", {"msg": "another_secret"})
        r = host.invoke("chp.adapters.audit.get_invocation",
                        {"invocation_id": result.invocation_id})
        dump = str(r.data["events"])
        assert "another_secret" not in dump
        assert "payload" not in dump

    def test_not_found_fails(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.get_invocation",
                        {"invocation_id": "nonexistent-id"})
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 4. stats
# --------------------------------------------------------------------------

class TestStats:
    def test_empty_store_returns_zeros(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.stats", {})
        assert r.outcome == "success"
        assert r.data["total_invocations"] == 0
        assert r.data["error_rate"] == 0.0

    def test_counts_invocations(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        host.invoke("chp.adapters.echo.ping", {"msg": "b"})
        host.invoke("chp.adapters.echo.fail", {})
        r = host.invoke("chp.adapters.audit.stats", {})
        assert r.data["total_invocations"] >= 3

    def test_by_outcome_present(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        r = host.invoke("chp.adapters.audit.stats", {})
        assert "by_outcome" in r.data

    def test_by_capability_sorted_desc(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "a"})
        host.invoke("chp.adapters.echo.ping", {"msg": "b"})
        host.invoke("chp.adapters.echo.fail", {})
        r = host.invoke("chp.adapters.audit.stats", {})
        by_cap = r.data["by_capability"]
        if len(by_cap) > 1:
            assert by_cap[0]["count"] >= by_cap[1]["count"]

    def test_error_rate_computed(self):
        host = _make_host()
        host.invoke("chp.adapters.echo.ping", {"msg": "ok"})
        host.invoke("chp.adapters.echo.fail", {})
        r = host.invoke("chp.adapters.audit.stats", {})
        assert 0.0 <= r.data["error_rate"] <= 1.0


# --------------------------------------------------------------------------
# 5. Evidence from audit adapter itself
# --------------------------------------------------------------------------

class TestAuditEvidence:
    def _audit_events(self, store):
        return [
            e for e in store.all()
            if e.get("capability_id", "").startswith("chp.adapters.audit")
            and e.get("event_type") not in ("execution_started", "execution_completed", "execution_failed")
        ]

    def test_query_emits_audit_events(self):
        host = _make_host()
        host.invoke("chp.adapters.audit.query_invocations", {})
        types = [e["event_type"] for e in self._audit_events(host.store)]
        assert "audit_query" in types
        assert "audit_result" in types

    def test_stats_emits_audit_events(self):
        host = _make_host()
        host.invoke("chp.adapters.audit.stats", {})
        types = [e["event_type"] for e in self._audit_events(host.store)]
        assert "audit_query" in types
        assert "audit_result" in types


# --------------------------------------------------------------------------
# 6. Injectable store
# --------------------------------------------------------------------------

class TestInjectableStore:
    def test_injectable_store_works(self):
        store = SQLiteEvidenceStore(":memory:")
        # Pre-populate store by creating a host and making calls
        host = LocalCapabilityHost(store=store)
        register_adapter(host, _EchoAdapter())
        host.invoke("chp.adapters.echo.ping", {"msg": "hello"})

        # Now create audit adapter with injected store (no host registration needed)
        audit = AuditAdapter(AuditConfig(store=store))
        audit_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(audit_host, audit)

        r = audit_host.invoke("chp.adapters.audit.query_invocations", {})
        assert r.outcome == "success"
        assert r.data["total"] >= 1


# --------------------------------------------------------------------------
# 7. token_report
# --------------------------------------------------------------------------

def _seed_http_response_events(store, entries):
    """Seed the store with synthetic http_response events for token_report tests."""
    from chp_core.types import ExecutionEvidence, CorrelationContext, new_id

    for entry in entries:
        payload = {
            "method": "POST",
            "url": "http://localhost:8092/v1/chat/completions",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 100,
            "truncated": False,
            "duration_ms": 250,
        }
        if "model" in entry:
            payload.update({
                "prompt_tokens": entry["prompt"],
                "completion_tokens": entry["completion"],
                "total_tokens": entry["prompt"] + entry["completion"],
                "model": entry["model"],
            })
        store.append(ExecutionEvidence(
            event_id=new_id("evt"),
            event_type="http_response",
            invocation_id=new_id("inv"),
            capability_id="chp.adapters.http.request",
            capability_version="1.0.0",
            host_id="test-host",
            correlation=CorrelationContext(),
            outcome="success",
            payload=payload,
            redacted=False,
        ))


class TestTokenReport:
    def _make_audit_with_store(self):
        store = SQLiteEvidenceStore(":memory:")
        audit = AuditAdapter(AuditConfig(store=store))
        audit_host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(audit_host, audit)
        return audit_host, store

    def test_empty_store_returns_zeros(self):
        host, _ = self._make_audit_with_store()
        r = host.invoke("chp.adapters.audit.token_report", {})
        assert r.outcome == "success"
        assert r.data["sovereign"]["total_tokens"] == 0
        assert r.data["sovereign"]["by_model"] == []
        assert r.data["estimated_frontier_cost_usd"] == 0.0
        assert r.data["backfill"]["calls_without_token_data"] == 0

    def test_aggregates_by_model(self):
        host, store = self._make_audit_with_store()
        _seed_http_response_events(store, [
            {"model": "fastcontext", "prompt": 100, "completion": 50},
            {"model": "fastcontext", "prompt": 200, "completion": 80},
            {"model": "vllm-qwen", "prompt": 300, "completion": 120},
        ])
        r = host.invoke("chp.adapters.audit.token_report", {})
        assert r.outcome == "success"
        by_model = {m["model"]: m for m in r.data["sovereign"]["by_model"]}
        assert by_model["fastcontext"]["prompt_tokens"] == 300
        assert by_model["fastcontext"]["completion_tokens"] == 130
        assert by_model["fastcontext"]["calls"] == 2
        assert by_model["vllm-qwen"]["calls"] == 1
        assert r.data["sovereign"]["total_prompt_tokens"] == 600
        assert r.data["sovereign"]["total_completion_tokens"] == 250

    def test_backfill_counts_events_without_tokens(self):
        host, store = self._make_audit_with_store()
        _seed_http_response_events(store, [
            {"model": "fastcontext", "prompt": 50, "completion": 20},
            {},  # no model/tokens — pre-tracking
            {},  # no model/tokens — pre-tracking
        ])
        r = host.invoke("chp.adapters.audit.token_report", {})
        assert r.data["backfill"]["calls_without_token_data"] == 2

    def test_frontier_cost_calculation(self):
        host, store = self._make_audit_with_store()
        _seed_http_response_events(store, [
            {"model": "fastcontext", "prompt": 1_000_000, "completion": 1_000_000},
        ])
        # Default: $3/1M input, $15/1M output → $3 + $15 = $18
        r = host.invoke("chp.adapters.audit.token_report", {})
        assert r.data["estimated_frontier_cost_usd"] == 18.0

    def test_custom_pricing(self):
        host, store = self._make_audit_with_store()
        _seed_http_response_events(store, [
            {"model": "fastcontext", "prompt": 1_000_000, "completion": 0},
        ])
        r = host.invoke("chp.adapters.audit.token_report", {
            "frontier_price_per_1m_input": 5.0,
            "frontier_price_per_1m_output": 20.0,
        })
        assert r.data["estimated_frontier_cost_usd"] == 5.0
