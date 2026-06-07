"""Tests for RuleBasedSafetyEvaluator and safety capability — §8.6."""

from __future__ import annotations

import pytest

from chp_core.safety import RuleBasedSafetyEvaluator, register_safety_capability
from chp_core.types import GuardrailDefinition


def test_assess_low_risk_capability():
    e = RuleBasedSafetyEvaluator()
    result = e.assess("retrieval.query", {"query": "hello world"})
    assert result.level == "low"
    assert result.score < 0.3
    assert result.recommendation == "allow"
    assert result.assessed_at.endswith("Z")


def test_assess_bash_is_elevated_risk():
    e = RuleBasedSafetyEvaluator()
    result = e.assess("claude_code.bash", {"command": "echo hello"})
    assert result.level in ("medium", "high", "critical")
    assert result.score >= 0.4


def test_payload_keyword_escalates_score():
    e = RuleBasedSafetyEvaluator()
    result = e.assess("files.read", {"path": "rm -rf /important"})
    assert result.level in ("high", "critical")
    assert any("rm -rf" in f for f in result.factors)


def test_guardrail_blocks_when_level_exceeds_max():
    g = GuardrailDefinition(
        id="bash-guard",
        capability_id_pattern="claude_code.*",
        max_risk_level="low",
    )
    e = RuleBasedSafetyEvaluator(guardrails=[g])
    assessment = e.assess("claude_code.bash", {"command": "ls"})
    approved, reason, evaluated = e.evaluate_guardrails("claude_code.bash", assessment)
    assert "bash-guard" in evaluated
    if assessment.level != "low":
        assert not approved
        assert reason is not None
        assert "bash-guard" in reason


def test_guardrail_passes_when_under_max():
    g = GuardrailDefinition(
        id="read-guard",
        capability_id_pattern="retrieval.*",
        max_risk_level="high",
    )
    e = RuleBasedSafetyEvaluator(guardrails=[g])
    assessment = e.assess("retrieval.query", {"query": "hello"})
    approved, reason, evaluated = e.evaluate_guardrails("retrieval.query", assessment)
    assert approved
    assert reason is None
    assert "read-guard" in evaluated


def test_guardrail_non_matching_pattern_is_skipped():
    g = GuardrailDefinition(
        id="bash-guard",
        capability_id_pattern="claude_code.*",
        max_risk_level="low",
    )
    e = RuleBasedSafetyEvaluator(guardrails=[g])
    assessment = e.assess("retrieval.query", {"query": "test"})
    approved, reason, evaluated = e.evaluate_guardrails("retrieval.query", assessment)
    assert approved
    assert "bash-guard" not in evaluated


def test_report_includes_payload_hash_and_id():
    e = RuleBasedSafetyEvaluator()
    report = e.report("retrieval.query", {"query": "test"})
    assert report.payload_hash.startswith("sha256:")
    assert report.report_id.startswith("sr_")
    assert report.generated_at.endswith("Z")


def test_report_to_dict_contains_nested_assessment():
    e = RuleBasedSafetyEvaluator()
    report = e.report("retrieval.query", {"query": "test"})
    d = report.to_dict()
    assert "assessment" in d
    assert d["assessment"]["level"] in ("low", "medium", "high", "critical")
    assert isinstance(d["assessment"]["score"], float)
    assert isinstance(d["assessment"]["factors"], list)


@pytest.mark.asyncio
async def test_safety_via_host():
    import os
    import tempfile

    from chp_core import LocalCapabilityHost, SQLiteEvidenceStore

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        path = f.name
    try:
        store = SQLiteEvidenceStore(path)
        host = LocalCapabilityHost("test-safety", store=store)
        register_safety_capability(host)

        result = await host.ainvoke(
            "safety.assess",
            {"capability_id": "retrieval.query", "payload": {"query": "hello"}},
        )
        assert result.success
        assert result.data["level"] == "low"
        assert result.data["recommendation"] == "allow"

        store.close()
    finally:
        os.unlink(path)
