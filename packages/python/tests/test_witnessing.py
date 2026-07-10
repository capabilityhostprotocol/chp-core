"""Mesh witnessing (chp-v0.2.md §12, proposal 0005): store heads, the
chain-witness statement, receipt dispositions, and the HTTP exchange."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore, signing, witnessing
from chp_core.types import CorrelationContext, InvocationEnvelope


def _key(offset: int = 0) -> signing.HostKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                           public_key_b64=pub, _private=priv)


def _host_with_history(host_id: str = "audited") -> LocalCapabilityHost:
    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="w.cap", version="1.0.0", description="."), handler)
    for corr in ("corr-one", "corr-two", "corr-three"):
        asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="w.cap", payload={},
            correlation=CorrelationContext(correlation_id=corr))))
    return host


def _witness(host, key, witness_id="peer-w") -> tuple[dict, dict]:
    head = host.store.get_store_head()
    stmt = signing.build_chain_witness(
        host.host_id, head["sequence"], head["store_head"], key,
        witness_id=witness_id, witnessed_at="2026-07-10T00:00:00Z")
    return stmt, head


class TestStoreHead:
    def test_as_of_n_is_stable_across_appends(self):
        host = _host_with_history()
        head = host.store.get_store_head()
        asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="w.cap", payload={},
            correlation=CorrelationContext(correlation_id="corr-later"))))
        again = host.store.get_store_head(at_sequence=head["sequence"])
        assert again["store_head"] == head["store_head"]
        assert "corr-later" not in again["leaves"]

    def test_rewriting_history_changes_the_head(self):
        host = _host_with_history()
        head = host.store.get_store_head()
        # attacker edits a hashed field of an old event directly in SQLite
        host.store._conn.execute(
            "UPDATE evidence_events SET content_hash = ? WHERE correlation_id = ? "
            "AND sequence = (SELECT MAX(sequence) FROM evidence_events WHERE correlation_id = ?)",
            ("0" * 64, "corr-one", "corr-one"))
        host.store._conn.commit()
        # The AUDIT path (fresh=True — what chp witness verify uses) recomputes
        # from raw events and MUST see the rewrite. The serving cache may not —
        # which is exactly why audits never trust it.
        assert host.store.get_store_head(
            at_sequence=head["sequence"], fresh=True)["store_head"] != head["store_head"]

    def test_serving_and_audit_paths_agree_on_honest_stores(self):
        host = _host_with_history()
        serving = host.store.get_store_head()
        audit = host.store.get_store_head(at_sequence=serving["sequence"], fresh=True)
        assert serving["store_head"] == audit["store_head"]
        assert serving["leaves"] == audit["leaves"]


class TestReceiptDispositions:
    def _receipt(self, host, key):
        stmt, head = _witness(host, key)
        return {"statement": stmt, "leaves": head["leaves"]}

    def test_intact_store_verifies(self):
        host = _host_with_history()
        r = witnessing.verify_receipt_against_store(host.store, self._receipt(host, _key()))
        assert r["verdict"] == "intact"
        assert r["dispositions"]["verified"] == 3
        assert r["dispositions"]["tampered"] == 0

    def test_purged_correlation_is_legal(self):
        host = _host_with_history()
        receipt = self._receipt(host, _key())
        host.store._conn.execute(
            "DELETE FROM evidence_events WHERE correlation_id = ?", ("corr-two",))
        host.store._conn.commit()
        r = witnessing.verify_receipt_against_store(host.store, receipt)
        assert r["verdict"] == "intact"
        assert r["dispositions"]["purged"] == 1
        assert r["dispositions"]["verified"] == 2

    def test_redacted_head_is_legal(self):
        host = _host_with_history()
        receipt = self._receipt(host, _key())
        host.store._conn.execute(
            "UPDATE evidence_events SET content_hash = NULL WHERE correlation_id = ?",
            ("corr-three",))
        host.store._conn.commit()
        r = witnessing.verify_receipt_against_store(host.store, receipt)
        assert r["verdict"] == "intact"
        assert r["dispositions"]["redacted"] == 1

    def test_rewritten_hash_is_tampered(self):
        host = _host_with_history()
        receipt = self._receipt(host, _key())
        host.store._conn.execute(
            "UPDATE evidence_events SET content_hash = ? WHERE correlation_id = ? "
            "AND sequence = (SELECT MAX(sequence) FROM evidence_events WHERE correlation_id = ?)",
            ("f" * 64, "corr-one", "corr-one"))
        host.store._conn.commit()
        r = witnessing.verify_receipt_against_store(host.store, receipt)
        assert r["verdict"] == "tampered"
        assert "corr-one" in r["tampered_correlations"]

    def test_inserted_history_is_tampered(self):
        host = _host_with_history()
        receipt = self._receipt(host, _key())
        # attacker inserts a backdated event with a LOW sequence
        host.store._conn.execute(
            "INSERT INTO evidence_events (sequence, event_id, event_type, invocation_id,"
            " capability_id, host_id, correlation_id, timestamp, payload_json, event_json,"
            " content_hash) VALUES (0, 'evt_forged', 'execution_started', 'inv_f', 'w.cap',"
            " 'audited', 'corr-forged', '2020-01-01T00:00:00Z', '{}', '{}', ?)",
            ("a" * 64,))
        host.store._conn.commit()
        r = witnessing.verify_receipt_against_store(host.store, receipt)
        assert r["verdict"] == "tampered"
        assert "corr-forged" in r["tampered_correlations"]

    def test_doctored_snapshot_is_flagged(self):
        host = _host_with_history()
        receipt = self._receipt(host, _key())
        receipt["leaves"]["corr-one"] = "b" * 64  # snapshot edited post-hoc
        r = witnessing.verify_receipt_against_store(host.store, receipt)
        assert r["verdict"] == "snapshot_invalid"


class TestWitnessRoutes:
    def _served(self, host):
        from chp_core.http import create_http_server

        server = create_http_server(host, bind="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def _post(self, url, body):
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _get(self, url):
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())

    def test_head_witness_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHP_WITNESS_DIR", str(tmp_path))
        host = _host_with_history()
        server, base = self._served(host)
        try:
            head = self._get(f"{base}/head")
            assert head["scheme"] == "chp-store-head-v1"
            assert head["sequence"] > 0
            stmt = signing.build_chain_witness(
                head["host_id"], head["sequence"], head["store_head"], _key(),
                witness_id="peer-w", witnessed_at="2026-07-10T00:00:00Z")
            accepted = self._post(f"{base}/witness", stmt)
            assert accepted["accepted"] is True
            served = self._get(f"{base}/witnesses")
            assert len(served["witnesses"]) == 1
            assert served["witnesses"][0]["store_head"] == head["store_head"]
            assert "leaves" not in served["witnesses"][0]
        finally:
            server.shutdown()
            server.server_close()

    def test_witness_with_wrong_head_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHP_WITNESS_DIR", str(tmp_path))
        host = _host_with_history()
        server, base = self._served(host)
        try:
            head = self._get(f"{base}/head")
            stmt = signing.build_chain_witness(
                head["host_id"], head["sequence"], "0" * 64, _key(),
                witness_id="peer-w", witnessed_at="2026-07-10T00:00:00Z")
            with pytest.raises(urllib.error.HTTPError) as exc:
                self._post(f"{base}/witness", stmt)
            assert exc.value.code == 409
            assert witnessing.load_received() == []
        finally:
            server.shutdown()
            server.server_close()

    def test_witness_for_wrong_host_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHP_WITNESS_DIR", str(tmp_path))
        host = _host_with_history()
        server, base = self._served(host)
        try:
            head = self._get(f"{base}/head")
            stmt = signing.build_chain_witness(
                "someone-else", head["sequence"], head["store_head"], _key(),
                witness_id="peer-w", witnessed_at="2026-07-10T00:00:00Z")
            with pytest.raises(urllib.error.HTTPError) as exc:
                self._post(f"{base}/witness", stmt)
            assert exc.value.code == 400
        finally:
            server.shutdown()
            server.server_close()
