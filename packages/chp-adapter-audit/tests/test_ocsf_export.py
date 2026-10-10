"""Tests for chp.adapters.audit.ocsf_export — governed decisions → OCSF 1.3.0 API Activity."""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_audit import AuditAdapter
from chp_adapter_audit._ocsf import (
    CATEGORY_UID_APPLICATION_ACTIVITY,
    CLASS_UID_API_ACTIVITY,
    OCSF_VERSION,
    decision_to_ocsf,
    ocsf_conformance,
)


def _make_host():
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, AuditAdapter())
    return host


# --------------------------------------------------------------------------
# Pure mapping
# --------------------------------------------------------------------------

class TestMapping:
    def test_allow_maps_to_success(self):
        ev = decision_to_ocsf({"op": "http.get", "decision": "ALLOW", "capability": "chp.adapters.http.request"},
                              source="cell-1")
        assert ev["category_uid"] == CATEGORY_UID_APPLICATION_ACTIVITY
        assert ev["class_uid"] == CLASS_UID_API_ACTIVITY
        assert ev["type_uid"] == ev["class_uid"] * 100 + ev["activity_id"]
        assert ev["status_id"] == 1
        assert ev["activity_id"] == 2  # a read op
        assert ev["api"]["operation"] == "chp.adapters.http.request"
        # governed decision is preserved verbatim as an enrichment
        assert ev["enrichments"][0]["data"]["decision"] == "ALLOW"

    def test_deny_maps_to_failure_and_medium_severity(self):
        ev = decision_to_ocsf({"op": "capability", "decision": "DENY", "capability": "chp.adapters.process.run"},
                              source="cell-1")
        assert ev["status_id"] == 2
        assert ev["severity_id"] == 3        # a denied effect is more notable
        assert ev["activity_id"] == 99       # non-read op

    def test_secret_ref_operation(self):
        ev = decision_to_ocsf({"decision": "ALLOW", "secret_ref": "secrets/openai"}, source="cell-1")
        assert ev["api"]["operation"] == "secrets/openai"

    def test_every_mapped_event_is_conformant(self):
        for dec in [
            {"op": "http.get", "decision": "ALLOW", "capability": "c"},
            {"op": "capability", "decision": "DENY", "capability": "c"},
            {"decision": "ALLOW", "secret_ref": "s"},
            {"decision": "DENY"},            # bare decision, no target
        ]:
            ok, problems = ocsf_conformance(decision_to_ocsf(dec, source="s"))
            assert ok, problems

    def test_conformance_rejects_broken_identity(self):
        ev = decision_to_ocsf({"decision": "ALLOW", "op": "http.get"}, source="s")
        ev["type_uid"] = 1  # break the class*100+activity identity
        ok, problems = ocsf_conformance(ev)
        assert not ok
        assert any("type_uid" in p for p in problems)

    def test_unknown_keys_preserved(self):
        ev = decision_to_ocsf({"decision": "ALLOW", "op": "effect", "nonce": "abc", "url": "https://x"},
                              source="s")
        data = ev["enrichments"][0]["data"]
        assert data["nonce"] == "abc" and data["url"] == "https://x"


# --------------------------------------------------------------------------
# Governed capability
# --------------------------------------------------------------------------

class TestCapability:
    def test_export_via_host(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.ocsf_export", {
            "decisions": [
                {"op": "http.get", "decision": "ALLOW", "capability": "chp.adapters.http.request"},
                {"op": "capability", "decision": "DENY", "capability": "chp.adapters.process.run"},
            ],
            "source": "opencell/cell-xyz",
        })
        assert r.outcome == "success"
        d = r.data
        assert d["ocsf_version"] == OCSF_VERSION
        assert d["count"] == 2
        assert d["all_conformant"] is True
        assert d["nonconformant"] == []
        assert d["events"][0]["src_endpoint"]["svc_name"] == "opencell/cell-xyz"

    def test_empty_decisions_ok(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.ocsf_export", {"decisions": []})
        assert r.outcome == "success"
        assert r.data["count"] == 0 and r.data["all_conformant"] is True

    def test_non_array_decisions_rejected(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.ocsf_export", {"decisions": {"not": "a list"}})
        assert r.outcome != "success"

    def test_non_object_decision_rejected(self):
        host = _make_host()
        r = host.invoke("chp.adapters.audit.ocsf_export", {"decisions": ["not an object"]})
        assert r.outcome != "success"
