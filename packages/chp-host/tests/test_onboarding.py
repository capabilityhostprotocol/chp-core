"""Onboarding round-trip: Mode A generates an adapter from a toy module that
imports, registers, invokes with evidence, and passes source conformance —
the whole portable-onboarding contract in one test."""

from __future__ import annotations

import asyncio
import importlib
import sys
import textwrap
from pathlib import Path

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore, register_adapter

from chp_host.onboarding.onboard import generate_mode_a


def _toy_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "toyrepo"
    repo.mkdir()
    (repo / "toymod.py").write_text(textwrap.dedent('''
        """A toy library being onboarded."""

        def get_greeting(name: str) -> dict:
            """Return a greeting for name."""
            return {"greeting": f"hello {name}"}

        def create_widget(kind: str, size: int = 1) -> dict:
            """Create a widget (mutating — should infer high risk)."""
            return {"created": kind, "size": size}
    '''))
    return repo


def _generate(tmp_path: Path, namespace: str | None = None) -> Path:
    repo = _toy_repo(tmp_path)
    sys.path.insert(0, str(repo))
    try:
        importlib.invalidate_caches()
        pkg = generate_mode_a(str(repo), "toymod", ["get_greeting", "create_widget"],
                              "toy", str(tmp_path / "_onboarded"), namespace=namespace)
    finally:
        pass  # keep repo on sys.path — the generated adapter delegates to toymod
    return Path(pkg)


class TestModeARoundTrip:
    def test_generated_adapter_registers_invokes_and_evidences(self, tmp_path):
        pkg = _generate(tmp_path)
        code_dir = pkg / "chp_adapter_toy"
        sys.path.insert(0, str(pkg))
        try:
            importlib.invalidate_caches()
            mod = importlib.import_module("chp_adapter_toy")
            host = LocalCapabilityHost("onboard-test", store=SQLiteEvidenceStore(":memory:"))
            register_adapter(host, mod.ToyAdapter())

            r = asyncio.run(host.ainvoke("onboarded.toy.get_greeting", {"name": "chp"},
                                         correlation={"correlation_id": "ob-corr"}))
            assert r.success and r.data["result"] == {"greeting": "hello chp"}
            assert "toyrepo:toymod.py" in r.data["wraps"]  # provenance recorded

            events = host.store.by_correlation("ob-corr")
            assert any(e["event_type"] == "onboarded.toy.get_greeting_called" for e in events)
        finally:
            sys.path.remove(str(pkg))
            sys.modules.pop("chp_adapter_toy", None)
            sys.modules.pop("chp_adapter_toy.adapter", None)

    def test_generated_ids_stay_out_of_reserved_namespace(self, tmp_path):
        pkg = _generate(tmp_path)
        src = (pkg / "chp_adapter_toy" / "adapter.py").read_text()
        assert 'id="onboarded.toy.get_greeting"' in src
        assert 'adapter_id = "onboarded.toy"' in src
        assert "chp.adapters." not in src.replace("chp.adapters.http", "")  # governance §5

    def test_custom_namespace_flows_through(self, tmp_path):
        pkg = _generate(tmp_path, namespace="com.acme.toy")
        src = (pkg / "chp_adapter_toy" / "adapter.py").read_text()
        assert 'id="com.acme.toy.get_greeting"' in src
        assert '"com.acme.toy.get_greeting_called"' in src  # declared AND emitted

    def test_risk_inference(self, tmp_path):
        pkg = _generate(tmp_path)
        src = (pkg / "chp_adapter_toy" / "adapter.py").read_text()
        assert 'risk="low"' in src   # get_greeting
        assert 'risk="high"' in src  # create_widget

    def test_generated_adapter_passes_source_conformance(self, tmp_path):
        pkg = _generate(tmp_path)
        from chp_adapter_conformance import check_source_file
        violations = [v for v in check_source_file(pkg / "chp_adapter_toy" / "adapter.py")
                      if v.severity == "error"]
        assert not violations, f"generated adapter has conformance errors: {violations}"
