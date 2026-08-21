"""Per-profile deployment SLO declaration (hardening wave arc 5; NFR-006).

A deployment profile SHOULD declare its service-level objectives — availability, latency, evidence
freshness, retention — so they are explicit and inspectable rather than implied. The prod + staging
profiles carry an ``slo`` block; this asserts its shape. (Profiles are chp-dev deployment config,
excluded from the public mirror — skip cleanly there.)
"""

import json
from pathlib import Path

import pytest

PROFILES = Path(__file__).resolve().parents[3] / "profiles"
_REQUIRED = {"availability", "latency_ms_p50", "latency_ms_p99", "evidence_freshness_s", "retention_days"}

if not PROFILES.exists():
    pytest.skip("deployment profiles not present (public mirror)", allow_module_level=True)


@pytest.mark.parametrize("profile", ["prod-host.json", "staging-host.json"])
def test_profile_declares_slo(profile):
    slo = json.loads((PROFILES / profile).read_text()).get("slo")
    assert slo is not None, f"{profile} must declare an slo block (NFR-006)"
    assert _REQUIRED <= set(slo), f"{profile} slo missing keys: {_REQUIRED - set(slo)}"
    assert 0 < slo["latency_ms_p50"] < slo["latency_ms_p99"], "p50 must be a positive latency below p99"
    assert slo["retention_days"] > 0 and slo["evidence_freshness_s"] > 0
