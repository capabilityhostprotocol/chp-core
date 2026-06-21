"""Tests for chp_adapter_registry.adapter."""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_registry import RegistryAdapter, RegistryConfig


# --------------------------------------------------------------------------
# Minimal adapters to populate the host
# --------------------------------------------------------------------------

class _AlphaAdapter:
    adapter_id = "chp.adapters.alpha"

    @capability(
        id="chp.adapters.alpha.run",
        version="1.0.0",
        description="Alpha run.",
        category="utility",
        risk="low",
        tags=["alpha", "test"],
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def run(self, ctx, payload):
        return {"ok": True}

    def capabilities(self):
        from chp_core.adapters import HostedCapability
        from chp_core.decorators import adapt_callable, get_capability_descriptor
        import inspect
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            desc = get_capability_descriptor(method.__func__)
            if desc is not None:
                yield HostedCapability(descriptor=desc, handler=adapt_callable(method))


class _BetaAdapter:
    adapter_id = "chp.adapters.beta"

    @capability(
        id="chp.adapters.beta.action",
        version="1.0.0",
        description="Beta action.",
        category="integration",
        risk="medium",
        tags=["beta"],
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def action(self, ctx, payload):
        return {"ok": True}

    def capabilities(self):
        from chp_core.adapters import HostedCapability
        from chp_core.decorators import adapt_callable, get_capability_descriptor
        import inspect
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            desc = get_capability_descriptor(method.__func__)
            if desc is not None:
                yield HostedCapability(descriptor=desc, handler=adapt_callable(method))


def _make_host(config=None):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, _AlphaAdapter())
    register_adapter(host, _BetaAdapter())
    register_adapter(host, RegistryAdapter(config))
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. Shaping
# --------------------------------------------------------------------------

class TestShaping:
    def test_three_capabilities(self):
        ids = {c.descriptor.id for c in RegistryAdapter().capabilities()}
        assert ids == {
            "chp.adapters.registry.list_capabilities",
            "chp.adapters.registry.get_capability",
            "chp.adapters.registry.describe_host",
        }

    def test_all_risk_low(self):
        for cap in RegistryAdapter().capabilities():
            assert cap.descriptor.risk == "low"


# --------------------------------------------------------------------------
# 2. list_capabilities
# --------------------------------------------------------------------------

class TestListCapabilities:
    def test_returns_registered_capabilities(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {})
        assert r.outcome == "success"
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.alpha.run" in ids
        assert "chp.adapters.beta.action" in ids

    def test_own_caps_excluded_by_default(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.registry.list_capabilities" not in ids
        assert "chp.adapters.registry.get_capability" not in ids
        assert "chp.adapters.registry.describe_host" not in ids

    def test_own_caps_included_when_configured(self):
        host = _make_host(RegistryConfig(include_registry_capabilities=True))
        r = host.invoke("chp.adapters.registry.list_capabilities", {})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.registry.list_capabilities" in ids

    def test_filter_by_category(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {"category": "utility"})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.alpha.run" in ids
        assert "chp.adapters.beta.action" not in ids

    def test_filter_by_namespace(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities",
                        {"namespace": "chp.adapters.alpha"})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.alpha.run" in ids
        assert "chp.adapters.beta.action" not in ids

    def test_filter_by_tags(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {"tags": ["alpha"]})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.alpha.run" in ids
        assert "chp.adapters.beta.action" not in ids

    def test_filter_by_risk(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {"risk": "medium"})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.beta.action" in ids
        assert "chp.adapters.alpha.run" not in ids

    def test_limit_applied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {"limit": 1})
        assert len(r.data["capabilities"]) == 1

    def test_count_matches(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {})
        assert r.data["count"] == len(r.data["capabilities"])

    def test_descriptor_has_required_fields(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {})
        cap = next(c for c in r.data["capabilities"] if c["id"] == "chp.adapters.alpha.run")
        assert "id" in cap
        assert "version" in cap
        assert "description" in cap
        assert "risk" in cap

    def test_extra_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.list_capabilities", {"injected": "bad"})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 3. get_capability
# --------------------------------------------------------------------------

class TestGetCapability:
    def test_returns_descriptor(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.get_capability",
                        {"id": "chp.adapters.alpha.run"})
        assert r.outcome == "success"
        assert r.data["capability"]["id"] == "chp.adapters.alpha.run"

    def test_not_found_fails(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.get_capability", {"id": "nonexistent"})
        assert r.outcome == "failure"

    def test_descriptor_fields_present(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.get_capability",
                        {"id": "chp.adapters.beta.action"})
        cap = r.data["capability"]
        assert cap["risk"] == "medium"
        assert cap["category"] == "integration"


# --------------------------------------------------------------------------
# 4. describe_host
# --------------------------------------------------------------------------

class TestDescribeHost:
    def test_returns_host_dict(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.describe_host", {})
        assert r.outcome == "success"
        assert "id" in r.data
        assert "capabilities" in r.data

    def test_capabilities_list_present(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.describe_host", {})
        ids = {c["id"] for c in r.data["capabilities"]}
        assert "chp.adapters.alpha.run" in ids

    def test_extra_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.registry.describe_host", {"injected": "bad"})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 5. Evidence
# --------------------------------------------------------------------------

class TestEvidence:
    def _registry_events(self, store):
        return [
            e for e in store.all()
            if e.get("capability_id", "").startswith("chp.adapters.registry")
            and e.get("event_type") not in ("execution_started", "execution_completed")
        ]

    def test_list_emits_registry_events(self):
        host = _make_host()
        host.invoke("chp.adapters.registry.list_capabilities", {})
        types = [e["event_type"] for e in self._registry_events(host.store)]
        assert "registry_query" in types
        assert "registry_result" in types

    def test_get_emits_registry_events(self):
        host = _make_host()
        host.invoke("chp.adapters.registry.get_capability", {"id": "chp.adapters.alpha.run"})
        types = [e["event_type"] for e in self._registry_events(host.store)]
        assert "registry_query" in types
        assert "registry_result" in types

    def test_not_found_emits_registry_error(self):
        host = _make_host()
        host.invoke("chp.adapters.registry.get_capability", {"id": "none"})
        types = [e["event_type"] for e in self._registry_events(host.store)]
        assert "registry_error" in types
