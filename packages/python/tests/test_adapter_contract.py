"""Adapter operational contract (proposal 0038): a declared, host-ENFORCED execution
timeout; an advisory retry policy; and a per-adapter health() self-report with a
worst-wins, fail-safe rollup. Additive — a descriptor without these fields serializes
byte-identically to a pre-0038 descriptor."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (BaseAdapter, CapabilityDescriptor, HealthStatus, LocalCapabilityHost,
                      RetryPolicy, SQLiteEvidenceStore, aggregate_health)


def _run(coro):
    return asyncio.run(coro)


def _host() -> LocalCapabilityHost:
    return LocalCapabilityHost("t", store=SQLiteEvidenceStore(":memory:"))


def test_timeout_is_enforced_as_failure() -> None:
    host = _host()

    async def slow(_c, _p):
        await asyncio.sleep(0.5)
        return {"done": True}

    host.register(CapabilityDescriptor(id="slow.cap", version="1.0.0", description=".",
                                       timeout_s=0.05), slow)
    r = _run(host.ainvoke("slow.cap", {}))
    # a timeout is a FAILURE (the capability ran too long), not a governance denial
    assert r.outcome == "failure"
    assert "Timeout" in (r.error or {}).get("type", "")


def test_within_timeout_succeeds() -> None:
    host = _host()
    host.register(CapabilityDescriptor(id="fast.cap", version="1.0.0", description=".",
                                       timeout_s=1.0), lambda _c, _p: {"ok": 1})
    assert _run(host.ainvoke("fast.cap", {})).outcome == "success"


def test_no_timeout_declared_runs_unbounded() -> None:
    host = _host()

    async def work(_c, _p):
        await asyncio.sleep(0.02)
        return {"ok": 1}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), work)
    assert _run(host.ainvoke("w.cap", {})).outcome == "success"


def test_descriptor_round_trip_and_omit_when_absent() -> None:
    d = CapabilityDescriptor(id="c", version="1", description=".", timeout_s=30.0,
                             retry=RetryPolicy(max_attempts=3, backoff_s=1.5,
                                               retry_on=["host_unreachable"]))
    dd = d.to_dict()
    assert dd["timeout_s"] == 30.0
    assert dd["retry"] == {"max_attempts": 3, "backoff_s": 1.5, "retry_on": ["host_unreachable"]}
    # absent → omitted → byte-identical to a pre-0038 descriptor
    bare = CapabilityDescriptor(id="c", version="1", description=".").to_dict()
    assert "timeout_s" not in bare and "retry" not in bare
    d.timeout_s = None
    d.retry = None
    canon = lambda o: hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()
    assert canon(d.to_dict()) == canon(bare)


def test_retry_from_mapping_validates() -> None:
    assert RetryPolicy.from_mapping({"max_attempts": 5}).max_attempts == 5
    for bad in ("nope", 42, None):
        try:
            RetryPolicy.from_mapping(bad)  # type: ignore[arg-type]
            assert False
        except ValueError:
            pass


def test_adapter_health_default_and_override() -> None:
    class Good(BaseAdapter):
        adapter_id = "good"

    class Sick(BaseAdapter):
        adapter_id = "sick"

        def health(self) -> HealthStatus:
            return HealthStatus(status="degraded", detail="cache cold")

    assert Good().health().ok
    assert Sick().health().status == "degraded"
    assert Good().health().to_dict() == {"status": "healthy"}  # detail omitted when None


def test_aggregate_health_worst_wins_and_fail_safe() -> None:
    class Good(BaseAdapter):
        adapter_id = "good"

    class Degraded(BaseAdapter):
        adapter_id = "deg"

        def health(self) -> HealthStatus:
            return HealthStatus(status="degraded")

    class Broken(BaseAdapter):
        adapter_id = "broken"

        def health(self) -> HealthStatus:
            raise RuntimeError("boom")

    agg = aggregate_health([Good(), Degraded(), Broken()])
    assert agg["status"] == "unavailable"  # worst wins
    assert agg["adapters"]["good"]["status"] == "healthy"
    assert agg["adapters"]["deg"]["status"] == "degraded"
    # a health() that raises is unavailable, never crashes the rollup (fail-safe)
    assert agg["adapters"]["broken"]["status"] == "unavailable"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
