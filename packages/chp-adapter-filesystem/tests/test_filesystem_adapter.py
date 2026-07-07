"""Tests for chp_adapter_filesystem.adapter."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_filesystem import FilesystemAdapter, FilesystemConfig


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _make_host(config=None):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, FilesystemAdapter(config))
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# Path confinement (sibling-prefix + glob escape)
# --------------------------------------------------------------------------

class TestConfinement:
    def test_sibling_prefix_root_is_rejected(self, tmp_path):
        # allowed_roots=[.../data] must NOT admit sibling .../data-secret
        root = tmp_path / "data"
        root.mkdir()
        sibling = tmp_path / "data-secret"
        sibling.mkdir()
        secret = sibling / "s.txt"
        secret.write_text("top secret")
        host = _make_host(FilesystemConfig(allowed_roots=[str(root)]))
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(secret)})
        assert r.outcome == "failure"

    def test_path_inside_root_still_allowed(self, tmp_path):
        root = tmp_path / "data"
        root.mkdir()
        f = root / "ok.txt"
        f.write_text("fine")
        host = _make_host(FilesystemConfig(allowed_roots=[str(root)]))
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        assert r.outcome == "success"

    def test_glob_escape_paths_dropped(self, tmp_path):
        root = tmp_path / "data"
        root.mkdir()
        (root / "inside.txt").write_text("x")
        (tmp_path / "outside.txt").write_text("secret")
        host = _make_host(FilesystemConfig(allowed_roots=[str(root)]))
        r = host.invoke("chp.adapters.filesystem.glob_files", {"pattern": "../*", "base_path": str(root)})
        assert r.outcome == "success"
        # nothing outside the root leaks through the '../' escape
        assert not any("outside.txt" in f for f in r.data["files"])


# --------------------------------------------------------------------------
# 1. Shaping
# --------------------------------------------------------------------------

class TestShaping:
    def test_six_capabilities(self):
        ids = {c.descriptor.id for c in FilesystemAdapter().capabilities()}
        assert ids == {
            "chp.adapters.filesystem.read_file",
            "chp.adapters.filesystem.write_file",
            "chp.adapters.filesystem.list_directory",
            "chp.adapters.filesystem.stat_path",
            "chp.adapters.filesystem.grep",
            "chp.adapters.filesystem.glob_files",
        }

    def test_write_is_high_risk(self):
        caps = {c.descriptor.id: c.descriptor for c in FilesystemAdapter().capabilities()}
        assert caps["chp.adapters.filesystem.write_file"].risk == "high"

    def test_others_are_low_risk(self):
        caps = {c.descriptor.id: c.descriptor for c in FilesystemAdapter().capabilities()}
        for cap_id in [
            "chp.adapters.filesystem.read_file",
            "chp.adapters.filesystem.list_directory",
            "chp.adapters.filesystem.stat_path",
        ]:
            assert caps[cap_id].risk == "low"


# --------------------------------------------------------------------------
# 2. read_file
# --------------------------------------------------------------------------

class TestReadFile:
    def test_read_existing_file(self, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_text("hello world")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        assert r.outcome == "success"
        assert r.data["content"] == "hello world"
        assert r.data["size_bytes"] == 11

    def test_missing_file_fails(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(tmp_path / "nope.txt")})
        assert r.outcome == "failure"

    def test_directory_path_fails(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(tmp_path)})
        assert r.outcome == "failure"

    def test_file_too_large_fails(self, tmp_path):
        f = tmp_path / "big.txt"
        f.write_bytes(b"x" * 10)
        host = _make_host(FilesystemConfig(max_read_bytes=5))
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        assert r.outcome == "failure"

    def test_missing_path_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.read_file", {})
        assert r.outcome == "denied"

    def test_extra_field_denied(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("x")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(f), "injected": "bad"})
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 3. write_file
# --------------------------------------------------------------------------

class TestWriteFile:
    def test_write_new_file(self, tmp_path):
        path = str(tmp_path / "out.txt")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.write_file", {"path": path, "content": "new"})
        assert r.outcome == "success"
        assert r.data["created"] is True
        assert Path(path).read_text() == "new"

    def test_overwrite_existing_file(self, tmp_path):
        f = tmp_path / "existing.txt"
        f.write_text("old")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.write_file", {"path": str(f), "content": "new"})
        assert r.outcome == "success"
        assert r.data["created"] is False
        assert f.read_text() == "new"

    def test_create_parents(self, tmp_path):
        path = str(tmp_path / "deep" / "dir" / "file.txt")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.write_file", {
            "path": path, "content": "hi", "create_parents": True
        })
        assert r.outcome == "success"
        assert Path(path).read_text() == "hi"

    def test_content_too_large_fails(self, tmp_path):
        path = str(tmp_path / "big.txt")
        host = _make_host(FilesystemConfig(max_write_bytes=5))
        r = host.invoke("chp.adapters.filesystem.write_file", {
            "path": path, "content": "0123456789"
        })
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 4. list_directory
# --------------------------------------------------------------------------

class TestListDirectory:
    def test_list_empty_dir(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.list_directory", {"path": str(tmp_path)})
        assert r.outcome == "success"
        assert r.data["entries"] == []
        assert r.data["count"] == 0

    def test_list_files_and_dirs(self, tmp_path):
        (tmp_path / "file.txt").write_text("x")
        (tmp_path / "subdir").mkdir()
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.list_directory", {"path": str(tmp_path)})
        names = {e["name"] for e in r.data["entries"]}
        types = {e["name"]: e["type"] for e in r.data["entries"]}
        assert "file.txt" in names
        assert "subdir" in names
        assert types["file.txt"] == "file"
        assert types["subdir"] == "directory"

    def test_glob_pattern_filter(self, tmp_path):
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.py").write_text("x")
        (tmp_path / "c.txt").write_text("x")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.list_directory", {
            "path": str(tmp_path), "pattern": "*.py"
        })
        assert r.data["count"] == 2
        names = {e["name"] for e in r.data["entries"]}
        assert names == {"a.py", "b.py"}

    def test_nonexistent_dir_fails(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.list_directory", {
            "path": str(tmp_path / "nope")
        })
        assert r.outcome == "failure"

    def test_file_path_fails(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("x")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.list_directory", {"path": str(f)})
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 5. stat_path
# --------------------------------------------------------------------------

class TestStatPath:
    def test_stat_existing_file(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("hello")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.stat_path", {"path": str(f)})
        assert r.outcome == "success"
        assert r.data["exists"] is True
        assert r.data["type"] == "file"
        assert r.data["size_bytes"] == 5
        assert r.data["modified_at"] is not None

    def test_stat_directory(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.stat_path", {"path": str(tmp_path)})
        assert r.data["exists"] is True
        assert r.data["type"] == "directory"

    def test_stat_missing_path(self, tmp_path):
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.stat_path", {"path": str(tmp_path / "ghost")})
        assert r.outcome == "success"
        assert r.data["exists"] is False
        assert r.data["type"] is None


# --------------------------------------------------------------------------
# 6. Path allowlist (allowed_roots)
# --------------------------------------------------------------------------

class TestAllowedRoots:
    def test_path_outside_root_denied(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        host = _make_host(FilesystemConfig(allowed_roots=[str(allowed)]))
        # Try to read a file outside the allowed root
        other = tmp_path / "other.txt"
        other.write_text("secret")
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(other)})
        assert r.outcome == "failure"

    def test_path_inside_root_allowed(self, tmp_path):
        allowed = tmp_path / "sandbox"
        allowed.mkdir()
        f = allowed / "ok.txt"
        f.write_text("fine")
        host = _make_host(FilesystemConfig(allowed_roots=[str(allowed)]))
        r = host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        assert r.outcome == "success"
        assert r.data["content"] == "fine"

    def test_write_outside_root_denied(self, tmp_path):
        allowed = tmp_path / "sandbox"
        allowed.mkdir()
        host = _make_host(FilesystemConfig(allowed_roots=[str(allowed)]))
        r = host.invoke("chp.adapters.filesystem.write_file", {
            "path": str(tmp_path / "escape.txt"), "content": "bad"
        })
        assert r.outcome == "failure"

    def test_list_outside_root_denied(self, tmp_path):
        allowed = tmp_path / "sandbox"
        allowed.mkdir()
        host = _make_host(FilesystemConfig(allowed_roots=[str(allowed)]))
        r = host.invoke("chp.adapters.filesystem.list_directory", {"path": str(tmp_path)})
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 7. Evidence hygiene
# --------------------------------------------------------------------------

class TestEvidenceHygiene:
    def test_content_not_in_read_evidence(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("SECRET_CONTENT_XYZ")
        host = _make_host()
        host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "SECRET_CONTENT_XYZ" not in dump

    def test_content_not_in_write_evidence(self, tmp_path):
        host = _make_host()
        host.invoke("chp.adapters.filesystem.write_file", {
            "path": str(tmp_path / "out.txt"), "content": "WRITTEN_SECRET_ABC"
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "WRITTEN_SECRET_ABC" not in dump

    def test_fs_read_event_emitted(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("x")
        host = _make_host()
        host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "fs_read" in types

    def test_fs_write_event_emitted(self, tmp_path):
        host = _make_host()
        host.invoke("chp.adapters.filesystem.write_file", {
            "path": str(tmp_path / "f.txt"), "content": "x"
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "fs_write" in types

    def test_fs_access_denied_event_on_root_violation(self, tmp_path):
        allowed = tmp_path / "sandbox"
        allowed.mkdir()
        other = tmp_path / "other.txt"
        other.write_text("x")
        host = _make_host(FilesystemConfig(allowed_roots=[str(allowed)]))
        host.invoke("chp.adapters.filesystem.read_file", {"path": str(other)})
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "fs_access_denied" in types

    def test_no_lifecycle_events_in_evidence(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("x")
        host = _make_host()
        host.invoke("chp.adapters.filesystem.read_file", {"path": str(f)})
        lifecycle = {"execution_started", "execution_completed", "execution_failed"}
        types = {e["event_type"] for e in _cap_events(host.store)}
        assert not types & lifecycle, f"lifecycle events found: {types & lifecycle}"


# --------------------------------------------------------------------------
# 7. grep
# --------------------------------------------------------------------------

class TestGrep:
    def test_basic_grep(self, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    pass\n")
        (tmp_path / "b.py").write_text("def bar():\n    pass\n")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "def foo", "path": str(tmp_path),
        })
        assert r.outcome == "success"
        assert r.data["match_count"] >= 1
        files = [m["file"] for m in r.data["matches"]]
        assert any("a.py" in f for f in files)

    def test_grep_with_glob_filter(self, tmp_path):
        (tmp_path / "main.py").write_text("SECRET = 'value'\n")
        (tmp_path / "main.txt").write_text("SECRET = 'value'\n")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "SECRET", "path": str(tmp_path), "glob": "*.py",
        })
        assert r.outcome == "success"
        files = [m["file"] for m in r.data["matches"]]
        assert all(f.endswith(".py") for f in files)

    def test_grep_case_insensitive(self, tmp_path):
        (tmp_path / "f.py").write_text("Hello World\n")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "hello world", "path": str(tmp_path), "case_insensitive": True,
        })
        assert r.outcome == "success"
        assert r.data["match_count"] >= 1

    def test_grep_no_matches(self, tmp_path):
        (tmp_path / "f.py").write_text("nothing here\n")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "ZZZNOMATCH", "path": str(tmp_path),
        })
        assert r.outcome == "success"
        assert r.data["match_count"] == 0
        assert r.data["truncated"] is False

    def test_grep_match_text_not_in_evidence(self, tmp_path):
        # The pattern is stored in evidence (correct), but the matched line TEXT
        # from file content must never appear in emitted events.
        (tmp_path / "f.py").write_text("UNIQUE_LINE_CONTENT_99887766\n")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "UNIQUE_LINE", "path": str(tmp_path),
        })
        assert r.success
        assert r.data["match_count"] >= 1
        for evt in _cap_events(host.store):
            # match content ("UNIQUE_LINE_CONTENT_99887766") should not appear in events
            assert "UNIQUE_LINE_CONTENT_99887766" not in str(evt.get("payload", {}))

    def test_grep_denied_outside_allowed_root(self, tmp_path):
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "f.py").write_text("x")
        host = _make_host(FilesystemConfig(allowed_roots=[str(sandbox)]))
        r = host.invoke("chp.adapters.filesystem.grep", {
            "pattern": "x", "path": str(outside),
        })
        assert not r.success


# --------------------------------------------------------------------------
# 8. glob_files
# --------------------------------------------------------------------------

class TestGlobFiles:
    def test_recursive_glob(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "a.py").write_text("")
        (sub / "b.py").write_text("")
        (tmp_path / "c.txt").write_text("")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.glob_files", {
            "pattern": "**/*.py", "base_path": str(tmp_path),
        })
        assert r.outcome == "success"
        assert r.data["count"] == 2
        assert r.data["truncated"] is False
        py_files = r.data["files"]
        assert any("a.py" in f for f in py_files)
        assert any("b.py" in f for f in py_files)

    def test_glob_no_matches(self, tmp_path):
        (tmp_path / "f.txt").write_text("")
        host = _make_host()
        r = host.invoke("chp.adapters.filesystem.glob_files", {
            "pattern": "**/*.zzz", "base_path": str(tmp_path),
        })
        assert r.outcome == "success"
        assert r.data["count"] == 0

    def test_glob_denied_outside_allowed_root(self, tmp_path):
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        host = _make_host(FilesystemConfig(allowed_roots=[str(sandbox)]))
        r = host.invoke("chp.adapters.filesystem.glob_files", {
            "pattern": "**/*.py", "base_path": str(outside),
        })
        assert not r.success

    def test_glob_emits_fs_glob_event(self, tmp_path):
        (tmp_path / "f.py").write_text("")
        host = _make_host()
        host.invoke("chp.adapters.filesystem.glob_files", {
            "pattern": "*.py", "base_path": str(tmp_path),
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "fs_glob" in types
