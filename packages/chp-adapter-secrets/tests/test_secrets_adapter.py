"""Tests for chp_adapter_secrets — no external services required."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_secrets import (
    EnvBackend,
    FileBackend,
    KeychainBackend,
    MemoryBackend,
    SecretsAdapter,
    SecretsConfig,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _make_host(backend=None) -> LocalCapabilityHost:
    adapter = SecretsAdapter(SecretsConfig(backend=backend or MemoryBackend()))
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _events(host: LocalCapabilityHost, event_type: str | None = None) -> list[dict]:
    events = [e for e in host.store.all() if "capability_uri" not in e["payload"]]
    if event_type:
        return [e for e in events if e["event_type"] == event_type]
    return events


# --------------------------------------------------------------------------
# 1. Capability shaping
# --------------------------------------------------------------------------

class TestCapabilityShaping:
    def test_capability_ids(self):
        ids = {c.descriptor.id for c in SecretsAdapter().capabilities()}
        assert ids == {
            "chp.adapters.secrets.get",
            "chp.adapters.secrets.set",
            "chp.adapters.secrets.delete",
            "chp.adapters.secrets.list",
        }

    def test_adapter_id(self):
        assert SecretsAdapter().adapter_id == "chp.adapters.secrets"

    def test_get_is_low_risk(self):
        cap = next(c for c in SecretsAdapter().capabilities()
                   if c.descriptor.id == "chp.adapters.secrets.get")
        assert cap.descriptor.risk == "low"

    def test_set_is_medium_risk(self):
        cap = next(c for c in SecretsAdapter().capabilities()
                   if c.descriptor.id == "chp.adapters.secrets.set")
        assert cap.descriptor.risk == "medium"

    def test_delete_is_medium_risk(self):
        cap = next(c for c in SecretsAdapter().capabilities()
                   if c.descriptor.id == "chp.adapters.secrets.delete")
        assert cap.descriptor.risk == "medium"

    def test_list_is_low_risk(self):
        cap = next(c for c in SecretsAdapter().capabilities()
                   if c.descriptor.id == "chp.adapters.secrets.list")
        assert cap.descriptor.risk == "low"

    def test_adapter_category_is_security(self):
        assert SecretsAdapter().adapter_category == "security"


# --------------------------------------------------------------------------
# 2. get capability
# --------------------------------------------------------------------------

class TestGet:
    def test_get_existing_secret(self):
        host = _make_host(MemoryBackend({"DB_URL": "postgres://localhost/mydb"}))
        r = host.invoke("chp.adapters.secrets.get", {"key": "DB_URL"})
        assert r.outcome == "success"
        assert r.data["key"] == "DB_URL"
        assert r.data["value"] == "postgres://localhost/mydb"

    def test_get_missing_secret_fails(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.get", {"key": "MISSING"})
        assert r.outcome == "failure"

    def test_get_emits_found_true(self):
        host = _make_host(MemoryBackend({"TOKEN": "abc"}))
        host.invoke("chp.adapters.secrets.get", {"key": "TOKEN"})
        ev = _events(host, "secrets_get")
        assert len(ev) == 1
        assert ev[0]["payload"]["found"] is True
        assert ev[0]["payload"]["key"] == "TOKEN"

    def test_get_emits_found_false(self):
        host = _make_host()
        host.invoke("chp.adapters.secrets.get", {"key": "MISSING"})
        ev = _events(host, "secrets_get")
        assert ev[0]["payload"]["found"] is False

    def test_get_missing_key_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.get", {})
        assert r.outcome == "denied"

    def test_get_unknown_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.get", {"key": "K", "extra": True})
        assert r.outcome == "denied"

    def test_get_empty_key_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.get", {"key": ""})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 3. get evidence hygiene — value NEVER in evidence
# --------------------------------------------------------------------------

class TestGetEvidenceHygiene:
    def test_secret_value_never_in_evidence(self):
        secret = "super_secret_password_xyz987"
        host = _make_host(MemoryBackend({"PWD": secret}))
        host.invoke("chp.adapters.secrets.get", {"key": "PWD"})
        dump = str([e["payload"] for e in host.store.all()])
        assert secret not in dump

    def test_only_key_name_and_found_in_evidence(self):
        host = _make_host(MemoryBackend({"API_KEY": "tok_live_abc123"}))
        host.invoke("chp.adapters.secrets.get", {"key": "API_KEY"})
        ev = _events(host, "secrets_get")[0]
        assert set(ev["payload"].keys()) == {"key", "found"}


# --------------------------------------------------------------------------
# 4. set capability
# --------------------------------------------------------------------------

class TestSet:
    def test_set_stores_secret(self):
        backend = MemoryBackend()
        host = _make_host(backend)
        r = host.invoke("chp.adapters.secrets.set", {"key": "NEW_KEY", "value": "new_val"})
        assert r.outcome == "success"
        assert r.data["stored"] is True
        assert backend.get("NEW_KEY") == "new_val"

    def test_set_overwrites_existing(self):
        backend = MemoryBackend({"K": "old"})
        host = _make_host(backend)
        host.invoke("chp.adapters.secrets.set", {"key": "K", "value": "new"})
        assert backend.get("K") == "new"

    def test_set_emits_key_only(self):
        host = _make_host()
        host.invoke("chp.adapters.secrets.set", {"key": "MY_KEY", "value": "secret_value"})
        ev = _events(host, "secrets_set")
        assert ev[0]["payload"] == {"key": "MY_KEY"}

    def test_set_value_never_in_evidence(self):
        secret = "VERY_SECRET_VALUE_abc123xyz"
        host = _make_host()
        host.invoke("chp.adapters.secrets.set", {"key": "K", "value": secret})
        dump = str([e["payload"] for e in host.store.all()])
        assert secret not in dump

    def test_set_missing_key_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.set", {"value": "v"})
        assert r.outcome == "denied"

    def test_set_missing_value_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.set", {"key": "k"})
        assert r.outcome == "denied"

    def test_set_unknown_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.set", {"key": "k", "value": "v", "ttl": 60})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 5. delete capability
# --------------------------------------------------------------------------

class TestDelete:
    def test_delete_existing_key(self):
        backend = MemoryBackend({"TO_DEL": "val"})
        host = _make_host(backend)
        r = host.invoke("chp.adapters.secrets.delete", {"key": "TO_DEL"})
        assert r.outcome == "success"
        assert r.data["deleted"] is True
        assert backend.get("TO_DEL") is None

    def test_delete_missing_key_returns_false(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.delete", {"key": "NOPE"})
        assert r.outcome == "success"
        assert r.data["deleted"] is False

    def test_delete_emits_event(self):
        backend = MemoryBackend({"K": "v"})
        host = _make_host(backend)
        host.invoke("chp.adapters.secrets.delete", {"key": "K"})
        ev = _events(host, "secrets_delete")
        assert ev[0]["payload"] == {"key": "K", "deleted": True}

    def test_delete_missing_key_schema_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.delete", {})
        assert r.outcome == "denied"

    def test_delete_unknown_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.delete", {"key": "K", "force": True})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 6. list capability
# --------------------------------------------------------------------------

class TestList:
    def test_list_empty(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.list", {})
        assert r.outcome == "success"
        assert r.data["count"] == 0
        assert r.data["keys"] == []

    def test_list_all_keys(self):
        host = _make_host(MemoryBackend({"A": "1", "B": "2", "C": "3"}))
        r = host.invoke("chp.adapters.secrets.list", {})
        assert r.data["count"] == 3
        assert sorted(r.data["keys"]) == ["A", "B", "C"]

    def test_list_with_prefix(self):
        host = _make_host(MemoryBackend({
            "AWS_KEY": "k1", "AWS_SECRET": "s1", "DB_URL": "u1",
        }))
        r = host.invoke("chp.adapters.secrets.list", {"prefix": "AWS_"})
        assert r.data["count"] == 2
        assert sorted(r.data["keys"]) == ["AWS_KEY", "AWS_SECRET"]

    def test_list_prefix_no_match(self):
        host = _make_host(MemoryBackend({"A": "1"}))
        r = host.invoke("chp.adapters.secrets.list", {"prefix": "Z_"})
        assert r.data["count"] == 0
        assert r.data["keys"] == []

    def test_list_emits_event(self):
        host = _make_host(MemoryBackend({"X": "1", "Y": "2"}))
        host.invoke("chp.adapters.secrets.list", {})
        ev = _events(host, "secrets_list")
        assert ev[0]["payload"]["count"] == 2

    def test_list_unknown_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.secrets.list", {"limit": 10})
        assert r.outcome == "denied"

    def test_list_values_never_returned(self):
        host = _make_host(MemoryBackend({"K": "secret_value_xyz"}))
        r = host.invoke("chp.adapters.secrets.list", {})
        dump = str(r.data)
        assert "secret_value_xyz" not in dump


# --------------------------------------------------------------------------
# 7. set → get round-trip
# --------------------------------------------------------------------------

class TestRoundTrip:
    def test_set_then_get(self):
        host = _make_host()
        host.invoke("chp.adapters.secrets.set", {"key": "RT_KEY", "value": "rt_value"})
        r = host.invoke("chp.adapters.secrets.get", {"key": "RT_KEY"})
        assert r.data["value"] == "rt_value"

    def test_set_delete_get(self):
        host = _make_host()
        host.invoke("chp.adapters.secrets.set", {"key": "TMP", "value": "tmp_val"})
        host.invoke("chp.adapters.secrets.delete", {"key": "TMP"})
        r = host.invoke("chp.adapters.secrets.get", {"key": "TMP"})
        assert r.outcome == "failure"

    def test_overwrite_reflected_in_get(self):
        host = _make_host()
        host.invoke("chp.adapters.secrets.set", {"key": "K", "value": "v1"})
        host.invoke("chp.adapters.secrets.set", {"key": "K", "value": "v2"})
        r = host.invoke("chp.adapters.secrets.get", {"key": "K"})
        assert r.data["value"] == "v2"


# --------------------------------------------------------------------------
# 8. Backend: EnvBackend
# --------------------------------------------------------------------------

class TestEnvBackend:
    def test_env_backend_reads_environ(self):
        os.environ["_CHP_TEST_KEY"] = "env_value"
        try:
            host = _make_host(EnvBackend())
            r = host.invoke("chp.adapters.secrets.get", {"key": "_CHP_TEST_KEY"})
            assert r.data["value"] == "env_value"
        finally:
            del os.environ["_CHP_TEST_KEY"]

    def test_env_backend_set_writes_environ(self):
        host = _make_host(EnvBackend())
        host.invoke("chp.adapters.secrets.set", {"key": "_CHP_WRITE_KEY", "value": "written"})
        try:
            assert os.environ.get("_CHP_WRITE_KEY") == "written"
        finally:
            os.environ.pop("_CHP_WRITE_KEY", None)

    def test_env_backend_delete_removes_key(self):
        os.environ["_CHP_DEL_KEY"] = "gone"
        host = _make_host(EnvBackend())
        r = host.invoke("chp.adapters.secrets.delete", {"key": "_CHP_DEL_KEY"})
        assert r.data["deleted"] is True
        assert "_CHP_DEL_KEY" not in os.environ

    def test_env_backend_value_never_in_evidence(self):
        os.environ["_CHP_HYGIENE_KEY"] = "super_secret_env_value_abc"
        try:
            host = _make_host(EnvBackend())
            host.invoke("chp.adapters.secrets.get", {"key": "_CHP_HYGIENE_KEY"})
            dump = str([e["payload"] for e in host.store.all()])
            assert "super_secret_env_value_abc" not in dump
        finally:
            del os.environ["_CHP_HYGIENE_KEY"]


# --------------------------------------------------------------------------
# 9. Backend: FileBackend
# --------------------------------------------------------------------------

class TestFileBackend:
    def test_file_backend_reads_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"FILE_TOKEN": "file_secret_value"}, f)
            path = f.name
        try:
            host = _make_host(FileBackend(path))
            r = host.invoke("chp.adapters.secrets.get", {"key": "FILE_TOKEN"})
            assert r.data["value"] == "file_secret_value"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_file_backend_set_persists(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            path = f.name
        try:
            host = _make_host(FileBackend(path))
            host.invoke("chp.adapters.secrets.set", {"key": "NEW", "value": "persisted"})
            # Re-read from file
            with open(path) as fh:
                data = json.load(fh)
            assert data["NEW"] == "persisted"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_file_backend_read_only_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"K": "v"}, f)
            path = f.name
        try:
            host = _make_host(FileBackend(path, read_only=True))
            r = host.invoke("chp.adapters.secrets.set", {"key": "K2", "value": "v2"})
            assert r.outcome == "failure"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_file_backend_value_never_in_evidence(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"SECRET_FROM_FILE": "file_top_secret_abc"}, f)
            path = f.name
        try:
            host = _make_host(FileBackend(path))
            host.invoke("chp.adapters.secrets.get", {"key": "SECRET_FROM_FILE"})
            dump = str([e["payload"] for e in host.store.all()])
            assert "file_top_secret_abc" not in dump
        finally:
            Path(path).unlink(missing_ok=True)


# --------------------------------------------------------------------------
# 10. Default backend is platform-aware (Keychain on macOS, Memory elsewhere)
# --------------------------------------------------------------------------

class TestDefaultBackend:
    def test_default_backend_darwin_prefers_keychain(self, monkeypatch):
        import sys as _sys
        from chp_adapter_secrets.adapter import _default_backend
        from chp_adapter_secrets.backends import KeychainBackend
        monkeypatch.setattr(_sys, "platform", "darwin")
        # On macOS the Keychain is available; falls back to Memory only on init failure.
        assert isinstance(_default_backend(), (KeychainBackend, MemoryBackend))

    def test_default_backend_non_darwin_is_memory(self, monkeypatch):
        import sys as _sys
        from chp_adapter_secrets.adapter import _default_backend
        monkeypatch.setattr(_sys, "platform", "linux")
        assert isinstance(_default_backend(), MemoryBackend)

    def test_two_adapters_have_independent_stores(self):
        host1 = _make_host()
        host2 = _make_host()
        host1.invoke("chp.adapters.secrets.set", {"key": "K", "value": "host1_val"})
        r = host2.invoke("chp.adapters.secrets.get", {"key": "K"})
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 11. Backend: KeychainBackend (macOS only)
# --------------------------------------------------------------------------

_KEYCHAIN_TEST_KEY = "_CHP_TEST_KEYCHAIN_XYZ987"
_KEYCHAIN_SERVICE = "com.chp.secrets"


def _kc_cleanup():
    subprocess.run(
        ["security", "delete-generic-password", "-a", _KEYCHAIN_TEST_KEY, "-s", _KEYCHAIN_SERVICE],
        capture_output=True,
    )


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS Keychain only")
class TestKeychainBackend:
    def setup_method(self, _method):
        _kc_cleanup()

    def teardown_method(self, _method):
        _kc_cleanup()

    def test_non_macos_raises(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with pytest.raises(OSError, match="macOS"):
            KeychainBackend()

    def test_set_and_get(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, "kc_test_value")
        assert b.get(_KEYCHAIN_TEST_KEY) == "kc_test_value"

    def test_get_missing_returns_none(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        assert b.get("_CHP_NO_SUCH_KEY_XYZ") is None

    def test_overwrite(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, "old_val")
        b.set(_KEYCHAIN_TEST_KEY, "new_val")
        assert b.get(_KEYCHAIN_TEST_KEY) == "new_val"

    def test_delete_existing_returns_true(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, "to_delete")
        assert b.delete(_KEYCHAIN_TEST_KEY) is True
        assert b.get(_KEYCHAIN_TEST_KEY) is None

    def test_delete_missing_returns_false(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        assert b.delete("_CHP_NO_SUCH_KEY_XYZ") is False

    def test_list_tracks_added_keys(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, "val")
        assert _KEYCHAIN_TEST_KEY in b.list_keys()

    def test_list_removes_after_delete(self, tmp_path):
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, "val")
        b.delete(_KEYCHAIN_TEST_KEY)
        assert _KEYCHAIN_TEST_KEY not in b.list_keys()

    def test_value_never_in_evidence(self, tmp_path):
        secret_val = "super_secret_keychain_value_abc123"
        b = KeychainBackend(index_path=tmp_path / "idx.json")
        b.set(_KEYCHAIN_TEST_KEY, secret_val)

        adapter = SecretsAdapter(SecretsConfig(backend=b))
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)

        r = host.invoke("chp.adapters.secrets.get", {"key": _KEYCHAIN_TEST_KEY})
        assert r.data["value"] == secret_val

        dump = str([e["payload"] for e in host.store.all()])
        assert secret_val not in dump
