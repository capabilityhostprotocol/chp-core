"""Tests for capability maturity assessment and certification — v0.4.5."""

from __future__ import annotations

import json
import pytest

from chp_core import (
    CertificationRecord,
    LocalCapabilityHost,
    MaturityAssessment,
    MaturityCriterion,
    SQLiteEvidenceStore,
    assess_maturity,
    register_retrieval_capability,
    InMemoryKeywordRetrievalCapability,
)
from chp_core.registry import RegistryEntry
from chp_core.types import CapabilityDescriptor, CapabilityCategory


# ── Fixtures ───────────────────────────────────────────────────────────────────


def _descriptor(
    cap_id: str = "test.cap",
    version: str = "1.0.0",
    description: str = "Test capability",
    category: str | None = CapabilityCategory.DATA_KNOWLEDGE,
    tags: list[str] | None = None,
    emits: list[str] | None = None,
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        id=cap_id,
        version=version,
        description=description,
        category=category,
        tags=tags if tags is not None else ["test"],
        emits=emits if emits is not None else [
            "execution_started", "execution_completed",
            "execution_failed", "execution_denied",
            "test.domain_event",
        ],
    )


def _events(n_started: int = 1, n_completed: int = 1, extra_types: list[str] | None = None) -> list[dict]:
    events = []
    for _ in range(n_started):
        events.append({"event_type": "execution_started", "payload": {}})
    for _ in range(n_completed):
        events.append({"event_type": "execution_completed", "payload": {}})
    for et in (extra_types or []):
        events.append({"event_type": et, "payload": {}})
    return events


# ── TestAssessMaturityLevels ───────────────────────────────────────────────────


class TestAssessMaturityLevels:
    def test_l1_passes_with_valid_descriptor(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=[])
        c = next(c for c in a.criteria if c.level == 1)
        assert c.passed

    def test_l1_fails_with_no_descriptor(self):
        a = assess_maturity("x", descriptor=None, events=[])
        c = next(c for c in a.criteria if c.level == 1)
        assert not c.passed

    def test_l1_fails_with_empty_description(self):
        d = _descriptor(description="")
        a = assess_maturity("x", descriptor=d, events=[])
        c = next(c for c in a.criteria if c.level == 1)
        assert not c.passed

    def test_l1_fails_with_empty_id(self):
        d = CapabilityDescriptor(id="", version="1.0.0", description="desc")
        a = assess_maturity("x", descriptor=d, events=[])
        assert not a.criteria[0].passed

    def test_l2_passes_with_execution_completed(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 2)
        assert c.passed

    def test_l2_fails_with_no_events(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=[])
        c = next(c for c in a.criteria if c.level == 2)
        assert not c.passed

    def test_l3_passes_with_domain_emits(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 3)
        assert c.passed

    def test_l3_fails_with_only_core_emits(self):
        d = _descriptor(emits=["execution_started", "execution_completed", "execution_failed"])
        a = assess_maturity("x", descriptor=d, events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 3)
        assert not c.passed

    def test_l4_passes_with_category_and_tags(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 4)
        assert c.passed

    def test_l4_fails_without_tags(self):
        d = _descriptor(tags=[])
        a = assess_maturity("x", descriptor=d, events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 4)
        assert not c.passed

    def test_l4_fails_without_category(self):
        d = _descriptor(category=None)
        a = assess_maturity("x", descriptor=d, events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 4)
        assert not c.passed

    def test_l5_passes_when_declared_emits_in_evidence(self):
        events = _events(1, 1, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events)
        c = next(c for c in a.criteria if c.level == 5)
        assert c.passed

    def test_l5_fails_when_declared_emit_missing_from_evidence(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=_events(1, 1))
        c = next(c for c in a.criteria if c.level == 5)
        assert not c.passed

    def test_l6_passes_with_ge10_execution_started(self):
        events = _events(10, 10, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events)
        c = next(c for c in a.criteria if c.level == 6)
        assert c.passed

    def test_l6_fails_with_fewer_than_10(self):
        events = _events(3, 3, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events)
        c = next(c for c in a.criteria if c.level == 6)
        assert not c.passed

    def test_l7_passes_with_certified_registry_entry(self):
        entry = RegistryEntry(id="x", certification_level=7)
        events = _events(10, 10, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events, registry_entry=entry)
        c = next(c for c in a.criteria if c.level == 7)
        assert c.passed

    def test_l7_fails_without_registry_entry(self):
        events = _events(10, 10, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events)
        c = next(c for c in a.criteria if c.level == 7)
        assert not c.passed

    def test_l7_fails_with_low_certification_level(self):
        entry = RegistryEntry(id="x", certification_level=5)
        events = _events(10, 10, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events, registry_entry=entry)
        c = next(c for c in a.criteria if c.level == 7)
        assert not c.passed


# ── TestAssessMaturityLevel ────────────────────────────────────────────────────


class TestAssessMaturityLevel:
    def test_level_0_when_no_descriptor(self):
        a = assess_maturity("x", descriptor=None, events=[])
        assert a.level == 0

    def test_level_1_with_only_descriptor(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=[])
        assert a.level == 1

    def test_level_2_with_descriptor_and_evidence(self):
        # Use only core emits → L3 fails, caps at L2
        d = _descriptor(emits=["execution_started", "execution_completed", "execution_failed", "execution_denied"])
        a = assess_maturity("x", descriptor=d, events=_events(1, 1))
        assert a.level == 2

    def test_level_caps_at_gap(self):
        # L3 fails (only core emits) → level caps at 2 even if L4+ would pass
        d = _descriptor(emits=["execution_started", "execution_completed"])
        a = assess_maturity("x", descriptor=d, events=_events(1, 1))
        assert a.level == 2

    def test_level_5_with_complete_emits(self):
        events = _events(1, 1, ["test.domain_event"])
        a = assess_maturity("x", descriptor=_descriptor(), events=events)
        assert a.level == 5

    def test_criteria_always_has_7_entries(self):
        a = assess_maturity("x", descriptor=None, events=[])
        assert len(a.criteria) == 7

    def test_all_criteria_passed_values_are_bool(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=_events(1, 1))
        for c in a.criteria:
            assert isinstance(c.passed, bool)

    def test_assessed_at_is_iso_string(self):
        a = assess_maturity("x", descriptor=_descriptor(), events=[])
        assert "T" in a.assessed_at


# ── TestMaturityAssessmentDataclass ────────────────────────────────────────────


class TestMaturityAssessmentDataclass:
    def test_to_dict_has_all_fields(self):
        a = assess_maturity("cap.x", descriptor=_descriptor(), events=_events(1, 1))
        d = a.to_dict()
        assert "capability_id" in d
        assert "level" in d
        assert "criteria" in d
        assert "evidence_count" in d
        assert "assessed_at" in d

    def test_criteria_in_dict_are_dicts(self):
        a = assess_maturity("cap.x", descriptor=_descriptor(), events=[])
        for c in a.to_dict()["criteria"]:
            assert isinstance(c, dict)
            assert "level" in c
            assert "passed" in c


# ── TestCertificationRecord ────────────────────────────────────────────────────


class TestCertificationRecord:
    def test_to_dict_has_required_fields(self):
        r = CertificationRecord(
            capability_id="test.cap",
            level=3,
            granted_by="alice",
            certified_at="2026-01-01T00:00:00Z",
        )
        d = r.to_dict()
        assert d["capability_id"] == "test.cap"
        assert d["level"] == 3
        assert d["granted_by"] == "alice"
        assert "certified_at" in d

    def test_notes_defaults_to_none(self):
        r = CertificationRecord(
            capability_id="x", level=1, granted_by="bob", certified_at="2026-01-01T00:00:00Z"
        )
        assert r.notes is None
        assert r.to_dict()["notes"] is None


# ── TestRegistryEntryExtension ─────────────────────────────────────────────────


class TestRegistryEntryExtension:
    def test_maturity_level_persists(self):
        entry = RegistryEntry(id="x", maturity_level=3)
        d = entry.to_dict()
        assert d["maturity_level"] == 3

    def test_certification_fields_persist(self):
        entry = RegistryEntry(
            id="x", certification_level=5,
            certified_by="alice", certified_at="2026-01-01T00:00:00Z",
            certification_notes="looks good",
        )
        d = entry.to_dict()
        assert d["certification_level"] == 5
        assert d["certified_by"] == "alice"
        assert d["certification_notes"] == "looks good"

    def test_none_certification_fields_omitted_from_dict(self):
        entry = RegistryEntry(id="x")
        d = entry.to_dict()
        assert "maturity_level" not in d
        assert "certification_level" not in d
        assert "certified_by" not in d

    def test_from_dict_round_trip(self):
        entry = RegistryEntry(id="x", maturity_level=2, certification_level=7, certified_by="bob")
        restored = RegistryEntry.from_dict(entry.to_dict())
        assert restored.maturity_level == 2
        assert restored.certification_level == 7
        assert restored.certified_by == "bob"

    def test_from_dict_defaults_none_for_missing_cert_fields(self):
        entry = RegistryEntry.from_dict({"id": "x", "enabled": True})
        assert entry.maturity_level is None
        assert entry.certification_level is None


# ── TestCertificationCLI ───────────────────────────────────────────────────────


class TestCertificationCLI:
    def test_certify_returns_0(self, tmp_path):
        import argparse
        from chp_core.cli._registry import cmd_registry_certify

        reg_path = str(tmp_path / "registry.json")
        args = argparse.Namespace(
            capability_id="test.cap",
            level=3,
            by="alice",
            notes="all good",
            registry=reg_path,
        )
        rc = cmd_registry_certify(args)
        assert rc == 0

    def test_certify_writes_to_registry(self, tmp_path):
        import argparse
        from chp_core.cli._registry import cmd_registry_certify
        from chp_core.registry import load_registry

        reg_path = str(tmp_path / "registry.json")
        args = argparse.Namespace(
            capability_id="cap.xyz",
            level=5,
            by="bob",
            notes=None,
            registry=reg_path,
        )
        cmd_registry_certify(args)

        entries = load_registry(reg_path)
        entry = next((e for e in entries if e.id == "cap.xyz"), None)
        assert entry is not None
        assert entry.certification_level == 5
        assert entry.certified_by == "bob"

    def test_certify_outputs_json(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._registry import cmd_registry_certify

        reg_path = str(tmp_path / "registry.json")
        args = argparse.Namespace(
            capability_id="cap.out",
            level=2,
            by="carol",
            notes=None,
            registry=reg_path,
        )
        cmd_registry_certify(args)
        out = json.loads(capsys.readouterr().out)
        assert out["capability_id"] == "cap.out"
        assert out["level"] == 2
        assert out["granted_by"] == "carol"

    def test_certify_rejects_invalid_level(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._registry import cmd_registry_certify

        reg_path = str(tmp_path / "registry.json")
        args = argparse.Namespace(
            capability_id="x",
            level=9,
            by=None,
            notes=None,
            registry=reg_path,
        )
        rc = cmd_registry_certify(args)
        assert rc == 1

    @pytest.mark.asyncio
    async def test_assess_maturity_outputs_level(self, tmp_path, capsys):
        import argparse
        from chp_core.cli._registry import cmd_registry_assess_maturity

        store_path = str(tmp_path / "ev.sqlite")
        reg_path = str(tmp_path / "registry.json")

        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("cli-cert", store=store)
        retrieval = InMemoryKeywordRetrievalCapability([])
        register_retrieval_capability(host, retrieval)
        await host.ainvoke("retrieval.query", {"query": "q"}, correlation={"correlation_id": "cert-1"})
        store.close()

        args = argparse.Namespace(
            capability_id="retrieval.query",
            store=store_path,
            registry=reg_path,
        )
        rc = cmd_registry_assess_maturity(args)
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert "level" in out
        assert "criteria" in out
        assert out["level"] >= 0


# ── Integration ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assess_maturity_from_real_evidence(tmp_path):
    """Run real invocations then assess maturity programmatically."""
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("int-cert", store=store)
    retrieval = InMemoryKeywordRetrievalCapability([])
    register_retrieval_capability(host, retrieval)

    corr = "int-cert-001"
    for _ in range(2):
        await host.ainvoke("retrieval.query", {"query": "hello"}, correlation={"correlation_id": corr})

    events = store.query(capability_id="retrieval.query")
    store.close()

    # No descriptor passed → L1 fails → level=0 is expected
    assessment = assess_maturity("retrieval.query", events=events)
    assert isinstance(assessment, MaturityAssessment)
    assert assessment.level >= 0
    assert len(assessment.criteria) == 7
    for c in assessment.criteria:
        assert isinstance(c.passed, bool)
