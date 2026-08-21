"""Live-host → capabilities.txt discovery, end-to-end (proposal 0053/wave; CHP-SUP-009/010/011).

A running CHP host self-publishes its semantic capabilities: discover() → host_capabilities_txt →
a discovery-only capabilities.txt document. Discovery advertises id/version/description + href
pointers, never an admission/authorization conclusion.
"""

from chp_core import (
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    host_capabilities_txt,
    project_capabilities_txt,
)
from chp_core.types import CapabilityDescriptor


def _host():
    h = LocalCapabilityHost("acme-host", store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, _p):
        return {"ok": True}

    h.register(CapabilityDescriptor(id="doc.summarize", version="1.2.0",
                                    description="Summarize a document"), handler)
    h.register(CapabilityDescriptor(id="image.classify", version="0.3.0",
                                    description="Classify an image"), handler)
    return h


def test_live_host_self_publishes_capabilities_txt():
    doc = host_capabilities_txt(_host().discover())
    assert doc["host"]["id"] == "acme-host"
    ids = {c["id"]: c for c in doc["capabilities"]}
    assert set(ids) == {"doc.summarize", "image.classify"}
    cap = ids["doc.summarize"]
    assert cap["version"] == "1.2.0" and cap["description"] == "Summarize a document"
    # discovery projects href pointers to bindings/offers, not the records themselves
    assert cap["bindings"]["href"].endswith("/doc.summarize/bindings")
    assert cap["offers"]["href"].endswith("/doc.summarize/offers")


def test_discovery_strips_non_projected_capability_fields():
    # A capability carrying an authorization conclusion has it STRIPPED by the projection — the
    # discovery surface only ever emits id/version/description + href pointers (safe by construction).
    bad_cap = {"id": "c", "version": "1", "description": "", "authorized": True, "grant": "g"}
    doc = host_capabilities_txt({"id": "h", "capabilities": [bad_cap]})
    out = doc["capabilities"][0]
    assert "authorized" not in out and "grant" not in out
    assert set(out) == {"id", "version", "description", "bindings", "offers"}


def test_projection_guard_rejects_forbidden_host_field():
    # The defensive guard fires if a forbidden conclusion reaches the OUTPUT (e.g. carried on host).
    import pytest
    with pytest.raises(ValueError):
        project_capabilities_txt(host={"id": "h", "authorized": True}, capabilities=[])


def test_host_and_manual_projection_agree():
    # The live-host bridge is exactly project_capabilities_txt over the descriptor's fields.
    h = _host()
    d = h.discover()
    manual = project_capabilities_txt(host={"id": d["id"]}, capabilities=d["capabilities"])
    live = host_capabilities_txt(d)
    assert live["capabilities"] == manual["capabilities"]
