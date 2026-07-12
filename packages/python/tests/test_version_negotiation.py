"""Wire-version negotiation (chp-v0.2.md §1.1, proposal 0016): declare →
select → reject."""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.http import create_http_server
from chp_core.types import (
    PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
    DenialReason,
    HostDescriptor,
    negotiate_version,
    versions_upto,
)


# ── the pure pieces ──────────────────────────────────────────────────────────

def test_negotiate_picks_highest_mutual():
    assert negotiate_version(["0.1", "0.2"], ["0.1", "0.2"]) == "0.2"
    assert negotiate_version(["0.1"], ["0.1", "0.2"]) == "0.1"          # client floor
    assert negotiate_version(["0.1", "0.2"], ["0.1"]) == "0.1"          # host floor
    assert negotiate_version(["0.2"], ["0.1", "0.2"]) == "0.2"


def test_negotiate_none_on_disjoint():
    assert negotiate_version(["0.1", "0.2"], ["9.9"]) is None
    assert negotiate_version([], ["0.2"]) is None


def test_negotiate_compares_by_major_minor_not_lexicographically():
    # "0.10" > "0.2" numerically though it sorts BEFORE as a string
    assert negotiate_version(["0.2", "0.10"], ["0.2", "0.10"]) == "0.10"


def test_versions_upto_is_additive_prefix():
    assert versions_upto("0.2") == ["0.1", "0.2"]
    assert versions_upto("0.1") == ["0.1"]
    assert versions_upto("9.9") == ["9.9"]           # outside the lineage → itself
    assert PROTOCOL_VERSION == "0.2" and SUPPORTED_VERSIONS[-1] == "0.2"


def test_version_unsupported_is_reserved():
    assert "version_unsupported" in DenialReason.RESERVED_CODES


def test_descriptor_declares_supported_versions():
    d = HostDescriptor(id="h").to_dict()
    assert d["supported_versions"] == ["0.1"]              # derived from default protocol_version
    d2 = HostDescriptor(id="h", protocol_version="0.2").to_dict()
    assert d2["supported_versions"] == ["0.1", "0.2"]
    d3 = HostDescriptor(id="h", supported_versions=["0.1", "0.2"]).to_dict()
    assert d3["supported_versions"] == ["0.1", "0.2"]     # explicit wins


# ── over the wire: declare / select / reject ─────────────────────────────────

@pytest.fixture()
def served():
    host = LocalCapabilityHost("ver-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_ctx, payload):
        return {"echo": payload}

    host.register(CapabilityDescriptor(id="ver.echo", version="1.0.0", description=""), echo)
    srv = create_http_server(host, bind="127.0.0.1", port=0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def _req(url, *, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_host_declares_supported_versions(served):
    status, desc = _req(f"{served}/host")
    assert status == 200
    # keyless host chains → hash-chain tier → speaks the full 0.1+0.2 lineage
    assert desc["supported_versions"] == ["0.1", "0.2"]
    assert desc["protocol_version"] == "0.2"


def test_supported_version_header_is_accepted(served):
    status, body = _req(f"{served}/invoke", method="POST",
                        body={"capability_id": "ver.echo", "payload": {"v": 1}},
                        headers={"X-CHP-Version": "0.2"})
    assert status == 200 and body.get("success") is True


def test_absent_header_processes_as_today(served):
    status, body = _req(f"{served}/invoke", method="POST",
                        body={"capability_id": "ver.echo", "payload": {"v": 1}})
    assert status == 200 and body.get("success") is True


def test_unsupported_version_header_rejected_400(served):
    status, body = _req(f"{served}/invoke", method="POST",
                        body={"capability_id": "ver.echo", "payload": {"v": 1}},
                        headers={"X-CHP-Version": "99.0"})
    assert status == 400
    assert body["denial"]["code"] == "version_unsupported"
    assert body["denial"]["requested"] == "99.0"


def test_client_negotiate_selects_and_declares(served):
    from chp_core.http import RemoteCapabilityHost

    client = RemoteCapabilityHost(served)
    assert client.negotiate() == "0.2"          # highest mutual with the host
    # subsequent invoke now declares X-CHP-Version: 0.2 and still succeeds
    res = client.invoke("ver.echo", {"v": 2})
    assert res.success
