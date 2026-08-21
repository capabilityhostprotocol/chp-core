"""The requirements-registry validator (hardening wave arc 2; RQC-004/006/008).

Proves the validator passes on the live registries AND catches each class of corruption it exists to
stop — so wiring it into CI turns "the requirements registries are consistent" from a hope into a gate.
"""

import csv
import json
import shutil
import sys
from pathlib import Path

import pytest

# The validator (scripts/) + the requirements registries (docs/product/) live in chp-dev only and
# are EXCLUDED from the public chp-core mirror. Skip cleanly there rather than fail the mirror's CI.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
rv = pytest.importorskip("requirements_validator", reason="requirements tooling is chp-dev-only")
if not rv.BASE.exists():
    pytest.skip("requirements registries not present (public mirror)", allow_module_level=True)


def _findings(base):
    return {f.check: f for f in rv.validate(base)}


def test_live_registries_pass():
    findings = _findings(rv.BASE)
    failed = [f.check for f in findings.values() if not f.ok]
    assert not failed, f"live registries fail: {failed} ({[findings[c].detail for c in failed]})"
    assert len(findings) >= 8


@pytest.fixture
def sandbox(tmp_path):
    """A writable copy of the three registries the validator reads."""
    for name in ("traceability_matrix.csv", "master_requirements.json", "requirement_graph.json",
                 "release_evidence.template.json"):
        shutil.copy(rv.BASE / name, tmp_path / name)
    return tmp_path


def _load_csv(base):
    return list(csv.DictReader((base / "traceability_matrix.csv").open()))


def _write_csv(base, rows):
    with (base / "traceability_matrix.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def test_catches_duplicate_id(sandbox):
    rows = _load_csv(sandbox)
    rows[1]["id"] = rows[0]["id"]  # collide two ids
    _write_csv(sandbox, rows)
    assert not _findings(sandbox)["duplicate_id"].ok


def test_catches_p0_without_test(sandbox):
    rows = _load_csv(sandbox)
    p0 = next(r for r in rows if r["criticality"] == "C0")
    p0["status"], p0["test_evidence"] = "implemented", ""   # a P0 implemented with no test
    _write_csv(sandbox, rows)
    f = _findings(sandbox)["p0_has_test"]
    assert not f.ok and p0["id"] in f.detail


def test_catches_registry_status_mismatch(sandbox):
    rows = _load_csv(sandbox)
    rows[0]["status"] = "implemented" if rows[0]["status"] != "implemented" else "baseline"
    _write_csv(sandbox, rows)   # CSV now disagrees with the untouched JSON
    assert not _findings(sandbox)["registry_agreement"].ok


def test_catches_dependency_cycle(sandbox):
    g = json.loads((sandbox / "requirement_graph.json").read_text())
    a, b = g["nodes"][0]["id"], g["nodes"][1]["id"]
    g["edges"] += [{"from": a, "to": b, "type": "depends_on"},
                   {"from": b, "to": a, "type": "depends_on"}]   # a 2-cycle
    (sandbox / "requirement_graph.json").write_text(json.dumps(g))
    assert not _findings(sandbox)["dependency_cycle"].ok


def test_catches_dangling_ref(sandbox):
    g = json.loads((sandbox / "requirement_graph.json").read_text())
    g["edges"].append({"from": g["nodes"][0]["id"], "to": "CHP-NOPE-999", "type": "depends_on"})
    (sandbox / "requirement_graph.json").write_text(json.dumps(g))
    assert not _findings(sandbox)["dangling_ref"].ok


def test_catches_uncovered_sec_threat(sandbox):
    # SEC-016: a SEC MUST threat left baseline (untested) is flagged as a coverage hole.
    rows = _load_csv(sandbox)
    sec = next(r for r in rows if r["domain"] == "SEC" and r["normative_level"] == "MUST")
    sec["status"], sec["test_evidence"] = "baseline", ""
    _write_csv(sandbox, rows)
    f = _findings(sandbox)["sec_threat_coverage"]
    assert not f.ok and sec["id"] in f.detail


def test_emit_release_evidence_projects_the_crosswalk():
    ev = rv.emit_release_evidence(rv.BASE, release="0.60.0")
    assert ev["release"] == "0.60.0"
    assert ev["requirements"] and all("requirement_id" in r and "evidence" in r for r in ev["requirements"])
    assert ev["gates"] and all({"gate", "implemented", "total"} <= set(g) for g in ev["gates"])
