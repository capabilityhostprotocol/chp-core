"""Tests for SafetyAdapter.

Uses RuleBasedSafetyEvaluator (the real implementation) since it is a pure
Python function with no side effects — no fake backend needed.
"""
from __future__ import annotations

import pytest
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.safety import RuleBasedSafetyEvaluator
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import GuardrailDefinition

from chp_adapter_safety import SafetyAdapter, SafetyConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host(config: SafetyConfig | None = None) -> LocalCapabilityHost:
    adapter = SafetyAdapter(config=config)
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _events(host: LocalCapabilityHost) -> list[dict]:
    return [e for e in host.store.all() if "capability_uri" not in e.get("payload", {})]


def _event_types(host: LocalCapabilityHost) -> list[str]:
    return [e["event_type"] for e in _events(host)]


# ---------------------------------------------------------------------------
# Capability registration
# ---------------------------------------------------------------------------

class TestRegistration:
    async def test_two_capabilities_registered(self):
        host = _make_host()
        keys = " ".join(host._capabilities.keys())
        assert "chp.adapters.safety.assess" in keys
        assert "chp.adapters.safety.report" in keys


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------

class TestAssess:
    async def test_low_risk_capability(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "chp.adapters.git.status",
            "payload": {"repo_path": "/home/user/project"},
        })
        assert result.outcome == "success"
        assert result.data["level"] in ("low", "medium", "high", "critical")
        assert "score" in result.data
        assert "recommendation" in result.data

    async def test_emits_assessment_started_and_completed(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "git.status",
        })
        types = _event_types(host)
        assert "safety_assessment_started" in types
        assert "safety_assessment_completed" in types

    async def test_low_risk_emits_approved(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "chp.adapters.git.log",
            "payload": {"repo_path": "/tmp/repo"},
        })
        assert "safety_action_approved" in _event_types(host)
        assert "safety_action_blocked" not in _event_types(host)

    async def test_critical_payload_emits_blocked(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "shell.exec",
            "payload": {"command": "rm -rf /"},
        })
        assert result.outcome == "success"
        types = _event_types(host)
        # "rm -rf" is a critical keyword → score >= 0.95 → blocked
        assert "safety_action_blocked" in types
        assert result.data["recommendation"] == "block"

    async def test_assessment_started_event_has_capability_id(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "my.cap.id",
        })
        ev = next(e for e in _events(host) if e["event_type"] == "safety_assessment_started")
        assert ev["payload"]["capability_id"] == "my.cap.id"

    async def test_assessment_completed_event_has_level_score_recommendation(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "git.status",
        })
        ev = next(e for e in _events(host) if e["event_type"] == "safety_assessment_completed")
        p = ev["payload"]
        assert "level" in p
        assert "score" in p
        assert "recommendation" in p

    async def test_no_payload_still_succeeds(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "some.cap",
        })
        assert result.outcome == "success"

    async def test_missing_capability_id_denied(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {})
        assert result.outcome == "denied"

    async def test_unknown_field_denied(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "x",
            "extra": True,
        })
        assert result.outcome == "denied"

    async def test_factors_list_in_result(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.assess", {
            "capability_id": "git.status",
        })
        assert isinstance(result.data["factors"], list)
        assert len(result.data["factors"]) >= 1


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

class TestReport:
    async def test_success(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "git.log",
        })
        assert result.outcome == "success"
        assert "report_id" in result.data
        assert "payload_hash" in result.data
        assert "approved" in result.data

    async def test_payload_hash_format(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "git.log",
            "payload": {"n": 10},
        })
        assert result.data["payload_hash"].startswith("sha256:")

    async def test_emits_full_event_chain(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "git.log",
        })
        types = _event_types(host)
        assert "safety_assessment_started" in types
        assert "safety_assessment_completed" in types

    async def test_approved_capability_emits_approved(self):
        host = _make_host()
        await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "chp.adapters.git.log",
        })
        assert "safety_action_approved" in _event_types(host)
        assert "safety_guardrail_triggered" not in _event_types(host)
        assert "safety_action_blocked" not in _event_types(host)

    async def test_blocked_by_guardrail(self):
        guardrail = GuardrailDefinition(
            id="g_test",
            capability_id_pattern="dangerous.*",
            max_risk_level="low",
        )
        config = SafetyConfig(guardrails=[guardrail])
        host = _make_host(config=config)
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "dangerous.delete",
        })
        assert result.outcome == "success"
        types = _event_types(host)
        assert "safety_guardrail_triggered" in types
        assert "safety_action_blocked" in types
        assert result.data["approved"] is False

    async def test_block_reason_in_blocked_event(self):
        guardrail = GuardrailDefinition(
            id="g_strict",
            capability_id_pattern="*delete*",
            max_risk_level="low",
        )
        config = SafetyConfig(guardrails=[guardrail])
        host = _make_host(config=config)
        await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "file.delete",
        })
        ev = next(e for e in _events(host) if e["event_type"] == "safety_action_blocked")
        assert "reason" in ev["payload"]
        assert ev["payload"]["reason"] is not None

    async def test_custom_evaluator_via_config(self):
        evaluator = RuleBasedSafetyEvaluator(
            high_risk_cap_patterns=["very_specific_pattern_*"],
        )
        config = SafetyConfig(evaluator=evaluator)
        host = _make_host(config=config)
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "git.status",
        })
        assert result.outcome == "success"

    async def test_guardrails_evaluated_list_in_result(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "git.log",
        })
        assert "guardrails_evaluated" in result.data
        assert isinstance(result.data["guardrails_evaluated"], list)

    async def test_missing_capability_id_denied(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.report", {})
        assert result.outcome == "denied"

    async def test_critical_keyword_not_approved(self):
        host = _make_host()
        result = await host.ainvoke("chp.adapters.safety.report", {
            "capability_id": "exec.shell",
            "payload": {"cmd": "drop table users"},
        })
        assert result.outcome == "success"
        assert result.data["assessment"]["level"] in ("high", "critical")
