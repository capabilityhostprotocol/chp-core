"""Tests for §13.5 Composability invariant — depends_on declaration on CapabilityDescriptor."""

from __future__ import annotations

import pytest

from chp_core import (
    CapabilityDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)


class TestDependsOnField:
    def test_depends_on_defaults_to_none(self):
        d = CapabilityDescriptor(id="x", version="1.0.0", description="test")
        assert d.depends_on is None

    def test_depends_on_round_trips_through_to_dict(self):
        d = CapabilityDescriptor(
            id="cap.b", version="1.0.0", description="B",
            depends_on=["cap.a"],
        )
        out = d.to_dict()
        assert "depends_on" in out
        assert out["depends_on"] == ["cap.a"]

    def test_depends_on_omitted_from_dict_when_none(self):
        d = CapabilityDescriptor(id="x", version="1.0.0", description="test")
        out = d.to_dict()
        assert "depends_on" not in out

    def test_depends_on_multiple_entries(self):
        d = CapabilityDescriptor(
            id="cap.c", version="1.0.0", description="C",
            depends_on=["cap.a", "cap.b"],
        )
        out = d.to_dict()
        assert out["depends_on"] == ["cap.a", "cap.b"]

    def test_empty_depends_on_list_included(self):
        d = CapabilityDescriptor(
            id="x", version="1.0.0", description="test",
            depends_on=[],
        )
        out = d.to_dict()
        assert "depends_on" in out
        assert out["depends_on"] == []


class TestDependsOnInDiscovery:
    def test_discover_includes_depends_on_when_set(self, tmp_path):
        store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
        host = LocalCapabilityHost("comp-host", store=store)

        async def _noop(ctx, payload):
            return {}

        host.register(
            CapabilityDescriptor(
                id="cap.a", version="1.0.0", description="A",
            ),
            _noop,
        )
        host.register(
            CapabilityDescriptor(
                id="cap.b", version="1.0.0", description="B",
                depends_on=["cap.a"],
            ),
            _noop,
        )
        store.close()

        descriptor = host.discover()
        caps = {c["id"]: c for c in descriptor["capabilities"]}
        assert "depends_on" not in caps["cap.a"], "cap.a should have no depends_on"
        assert "depends_on" in caps["cap.b"], "cap.b should have depends_on"
        assert caps["cap.b"]["depends_on"] == ["cap.a"]

    def test_discover_omits_depends_on_when_none(self, tmp_path):
        store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
        host = LocalCapabilityHost("comp-host-2", store=store)

        async def _noop(ctx, payload):
            return {}

        host.register(
            CapabilityDescriptor(id="x", version="1.0.0", description="X"),
            _noop,
        )
        store.close()

        descriptor = host.discover()
        cap = next(c for c in descriptor["capabilities"] if c["id"] == "x")
        assert "depends_on" not in cap


class TestVersionControlDependsOn:
    def test_verify_merge_readiness_depends_on_precommit(self):
        from chp_core.version_control import git_capabilities

        caps = {hc.descriptor.id: hc.descriptor for hc in git_capabilities()}
        vmr = caps["chp.version_control.verify_merge_readiness"]
        assert vmr.depends_on is not None
        assert "chp.version_control.precommit_check" in vmr.depends_on

    def test_release_tag_depends_on_release_bundle(self):
        from chp_core.version_control import git_capabilities

        caps = {hc.descriptor.id: hc.descriptor for hc in git_capabilities()}
        rt = caps["chp.version_control.release_tag"]
        assert rt.depends_on is not None
        assert "chp.version_control.release_evidence_bundle" in rt.depends_on

    def test_inspect_repo_has_no_depends_on(self):
        from chp_core.version_control import git_capabilities

        caps = {hc.descriptor.id: hc.descriptor for hc in git_capabilities()}
        assert caps["chp.version_control.inspect_repo"].depends_on is None
