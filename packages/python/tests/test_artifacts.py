"""Artifact data plane slice 1: content-addressed store + refs + wire endpoints."""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from chp_core import (ArtifactIntegrityError, ArtifactRef, ArtifactStore, LocalCapabilityHost,
                      SQLiteEvidenceStore, artifact_id_for)
from chp_core.http import create_http_server


def test_store_roundtrip_and_idempotent_put(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put(b"hello artifact", media_type="text/plain")
    assert ref.artifact_id == artifact_id_for(b"hello artifact")
    assert ref.size_bytes == 14 and ref.media_type == "text/plain"
    again = store.put(b"hello artifact")
    assert again.artifact_id == ref.artifact_id  # same bytes, same address
    data, media_type = store.get(ref.artifact_id)
    assert data == b"hello artifact" and media_type == "text/plain"


def test_tampered_artifact_is_refused_not_returned(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put(b"original")
    (store.root / ref.artifact_id.removeprefix("sha256:")).write_bytes(b"SWAPPED")
    with pytest.raises(ArtifactIntegrityError):
        store.get(ref.artifact_id)


def test_malformed_ids_rejected(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    with pytest.raises(ValueError):
        store.get("sha256:../../../etc/passwd")
    with pytest.raises(ValueError):
        store.get("md5:abc")
    with pytest.raises(ValueError):
        ArtifactRef(artifact_id="sha256:short")
    assert store.exists("garbage") is False


@pytest.fixture()
def served(tmp_path):
    host = LocalCapabilityHost("art-host", store=SQLiteEvidenceStore(":memory:"))
    host.artifacts = ArtifactStore(tmp_path / "artifacts")
    server = create_http_server(host, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", host
    server.shutdown()
    server.server_close()


def test_wire_upload_download_roundtrip(served):
    base, _ = served
    req = urllib.request.Request(f"{base}/artifacts", data=b"wire bytes",
                                 headers={"Content-Type": "text/plain"})
    with urllib.request.urlopen(req) as r:
        assert r.status == 201
        ref = json.loads(r.read())
    assert ref["artifact_id"] == artifact_id_for(b"wire bytes")
    with urllib.request.urlopen(f"{base}/artifacts/{ref['artifact_id']}") as r:
        assert r.read() == b"wire bytes"
        assert r.headers["Content-Type"] == "text/plain"


def test_wire_unknown_and_unsupported(served, tmp_path):
    base, host = served
    missing = artifact_id_for(b"never uploaded")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(f"{base}/artifacts/{missing}")
    assert e.value.code == 404
    assert json.loads(e.value.read())["error"]["code"] == "artifact_not_found"
    # A host WITHOUT a store: the plane is truthfully unsupported, not a no-op.
    bare = LocalCapabilityHost("bare", store=SQLiteEvidenceStore(":memory:"))
    server = create_http_server(bare, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError) as e2:
            urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/artifacts/{missing}")
        assert json.loads(e2.value.read())["error"]["code"] == "artifact_plane_unsupported"
    finally:
        server.shutdown()
        server.server_close()


def test_store_audience_roundtrip(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put(b"secret", media_type="text/plain", audience=["team-a", "svc.*"])
    assert store.access_of(ref.artifact_id) == ["team-a", "svc.*"]
    # Audience rides the meta, not the id — same bytes keep their content address.
    assert store.put(b"secret").artifact_id == ref.artifact_id
    # Unbounded artifact reports None.
    open_ref = store.put(b"public bytes")
    assert store.access_of(open_ref.artifact_id) is None
    with pytest.raises(FileNotFoundError):
        store.access_of(artifact_id_for(b"never stored"))


def test_retention_sweeps_old_keeps_fresh(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    old = store.put(b"old artifact", media_type="text/plain")
    fresh = store.put(b"fresh artifact", media_type="text/plain")
    # Backdate the old artifact's persisted created_at to 40 days ago.
    import json
    old_meta = store._path(old.artifact_id).with_suffix(".meta")
    d = json.loads(old_meta.read_text())
    d["created_at"] = "2020-01-01T00:00:00Z"
    old_meta.write_text(json.dumps(d))

    removed = store.apply_retention(max_age_days=30)
    assert removed == [old.artifact_id]
    assert not store.exists(old.artifact_id)          # digest file gone
    assert not old_meta.exists()                       # sidecar gone
    assert store.exists(fresh.artifact_id)             # fresh kept
    assert store.get(fresh.artifact_id)[0] == b"fresh artifact"


def test_created_at_persisted_and_read_back(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put(b"timestamped")
    _mt, _aud, created_at = store._read_meta(store._path(ref.artifact_id))
    assert created_at == ref.created_at and created_at.endswith("Z")


def test_wire_audience_gates_access_by_caller(tmp_path, monkeypatch):
    # Named+scoped API keys so the handler binds a verified caller identity.
    monkeypatch.setenv("CHP_HOST_API_KEYS", "team-a:key-a:chp.*,team-b:key-b:chp.*")
    host = LocalCapabilityHost("auth-art", store=SQLiteEvidenceStore(":memory:"))
    host.artifacts = ArtifactStore(tmp_path / "artifacts")
    server = create_http_server(host, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        # Upload restricted to team-a.
        up = urllib.request.Request(f"{base}/artifacts", data=b"for team-a only",
                                    headers={"X-CHP-Key": "key-a",
                                             "X-CHP-Artifact-Audience": "team-a"})
        with urllib.request.urlopen(up) as r:
            ref = json.loads(r.read())["artifact_id"]

        def fetch(key):
            req = urllib.request.Request(f"{base}/artifacts/{ref}",
                                         headers={"X-CHP-Key": key})
            return urllib.request.urlopen(req)

        with fetch("key-a") as r:              # in-audience caller: allowed
            assert r.read() == b"for team-a only"
        with pytest.raises(urllib.error.HTTPError) as e:  # authed but out-of-audience
            fetch("key-b")
        assert e.value.code == 403
        assert json.loads(e.value.read())["error"]["code"] == "artifact_access_denied"
    finally:
        server.shutdown()
        server.server_close()


def test_wire_tampered_artifact_is_conflict(served):
    base, host = served
    req = urllib.request.Request(f"{base}/artifacts", data=b"integrity")
    with urllib.request.urlopen(req) as r:
        ref = json.loads(r.read())
    (host.artifacts.root / ref["artifact_id"].removeprefix("sha256:")).write_bytes(b"EVIL")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(f"{base}/artifacts/{ref['artifact_id']}")
    assert e.value.code == 409
    assert json.loads(e.value.read())["error"]["code"] == "artifact_integrity_failed"
