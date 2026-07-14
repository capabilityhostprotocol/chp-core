"""Authorized discovery (proposal 0035). A host filters its discovered catalog to
what the verified caller may invoke: a capability whose descriptor.policy.allowed_actors
is non-empty and excludes the caller is HIDDEN. An anonymous caller (None) sees the
unfiltered catalog (backward-compatible). Hiding is least-disclosure; the invocation
gate (policy_blocked, proposal 0034) remains the security backstop."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.types import PolicyDescriptor


def _host() -> LocalCapabilityHost:
    h = LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))

    async def w(_c, _p):
        return {}

    h.register(CapabilityDescriptor(id="open.cap", version="1.0.0", description="."), w)
    h.register(CapabilityDescriptor(id="secret.cap", version="1.0.0", description=".",
                                    policy=PolicyDescriptor(allowed_actors=["alice"])), w)
    return h


def _ids(h: LocalCapabilityHost, caller) -> list[str]:
    return sorted(c["id"] for c in h.discover(caller=caller)["capabilities"])


def test_listed_caller_sees_restricted_capability() -> None:
    assert _ids(_host(), "alice") == ["open.cap", "secret.cap"]


def test_unlisted_caller_only_sees_open_capabilities() -> None:
    assert _ids(_host(), "mallory") == ["open.cap"]  # secret hidden


def test_anonymous_caller_sees_unfiltered_catalog() -> None:
    # Backward-compat: caller=None → today's behavior (everything visible).
    assert _ids(_host(), None) == ["open.cap", "secret.cap"]


def test_hidden_capability_still_denied_at_invoke() -> None:
    """Defense in depth: hiding is least-disclosure; a caller that guesses the id
    and invokes it is still denied policy_blocked (the M1 gate)."""
    import asyncio

    h = _host()
    r = asyncio.run(h.ainvoke("secret.cap", {}, actor={"id": "mallory", "type": "agent"}))
    assert r.outcome == "denied" and r.denial.code == "policy_blocked"


def test_authorized_discovery_vector_matches_shared_algorithm() -> None:
    vec = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "authorized-discovery.json"
    doc = json.loads(vec.read_text())

    def visible(c):
        if c.get("caller") is None:
            return True
        allowed = c.get("allowed_actors") or []
        return not allowed or c["caller"] in allowed

    for c in doc["cases"]:
        assert visible(c) is c["visible"], c["note"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
