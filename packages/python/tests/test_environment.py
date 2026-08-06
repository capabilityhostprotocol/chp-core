"""Environment as a protocol primitive: the canonical dev/test/pilot/prod tiers, consumed across the
stack (chp-platform ControlPlane, chp-home deploy channels), and stamped into CorrelationContext so
every invocation's evidence is provably attributed to its environment (schema + TS + spec aligned)."""
from __future__ import annotations

import pytest

from chp_core import ENVIRONMENTS, current_environment, validate_environment
from chp_core.types import CorrelationContext


def test_canonical_tiers():
    assert ENVIRONMENTS == ("dev", "test", "pilot", "prod")
    assert validate_environment("prod") == "prod"
    with pytest.raises(ValueError):
        validate_environment("staging")          # not a known tier → reject, don't run mis-tiered


def test_current_environment_from_env(monkeypatch):
    monkeypatch.delenv("CHP_ENV", raising=False)
    assert current_environment() == "dev"        # default
    monkeypatch.setenv("CHP_ENV", "pilot")
    assert current_environment() == "pilot"
    monkeypatch.setenv("CHP_ENV", "bogus")
    with pytest.raises(ValueError):
        current_environment()                    # invalid CHP_ENV fails loudly


def test_platform_control_plane_uses_canonical():
    """chp-platform consolidated onto the chp-core definition (no duplicate tuple)."""
    pytest.importorskip("chp_platform")          # sibling package; only when present
    from chp_platform.control_plane import ENVIRONMENTS as PLATFORM_ENVS
    assert PLATFORM_ENVS is ENVIRONMENTS         # same object → single source of truth


def test_correlation_stamps_environment(monkeypatch):
    monkeypatch.setenv("CHP_ENV", "prod")
    c = CorrelationContext()
    assert c.environment == "prod"
    assert c.to_dict()["environment"] == "prod"  # travels into evidence


def test_correlation_from_mapping_roundtrips(monkeypatch):
    monkeypatch.setenv("CHP_ENV", "dev")
    # explicit environment on the wire is preserved (a prod invocation stays prod on a dev reader)
    assert CorrelationContext.from_mapping({"correlation_id": "c", "environment": "prod"}).environment == "prod"
    # absent → the reader's current environment (backward-compat for pre-field correlations)
    assert CorrelationContext.from_mapping({"correlation_id": "c"}).environment == "dev"
