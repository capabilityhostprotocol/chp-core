"""Tests for chp-adapter-conformance."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from chp_adapter_conformance import (
    ConformanceAdapter,
    Violation,
    check_commit_message,
    check_registered_adapter,
    check_source_file,
    score,
)
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _src(code: str, tmp_path: Path) -> Path:
    p = tmp_path / "adapter.py"
    p.write_text(textwrap.dedent(code))
    return p


def _rules(violations: list[Violation]) -> set[str]:
    return {v.rule for v in violations}


def _make_host() -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, ConformanceAdapter())
    return host


def _invoke(host, cap_id, payload=None):
    return host.invoke(cap_id, payload or {})


# ---------------------------------------------------------------------------
# Static checker
# ---------------------------------------------------------------------------

class TestCheckSourceFile:
    def test_clean_adapter_no_violations(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert len(violations) == 0

    def test_detects_raw_open(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    with open("/tmp/foo") as f:
                        data = f.read()
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "raw_io" in _rules(violations)

    def test_detects_missing_emit(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "missing_emit" in _rules(violations)

    def test_detects_forbidden_import(self, tmp_path):
        src = _src("""
            import httpx
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "raw_http" in _rules(violations)

    def test_detects_silent_error(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    try:
                        pass
                    except Exception:
                        pass
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "silent_error" in _rules(violations)

    def test_detects_direct_host_call(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    ctx.host.some_method()
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "direct_host_call" in _rules(violations)

    def test_record_turn_is_sanctioned(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    ctx.host.record_turn(ctx.correlation_id, role="user", content="x")
                    ctx.emit("done", {})
                    return {"ok": True}
        """, tmp_path)
        violations = check_source_file(src)
        assert "direct_host_call" not in _rules(violations)

    def test_backfill_session_has_violations(self):
        """Confirm the known violation in backfill_session is detected."""
        from pathlib import Path
        root = Path(__file__).resolve().parents[3]  # chp-dev/
        path = root / "packages" / "chp-adapter-messages" / "chp_adapter_messages" / "adapter.py"
        if not path.exists():
            pytest.skip("chp-adapter-messages not available in test path")
        violations = check_source_file(path)
        # backfill_session now routes through ctx.ainvoke(filesystem.read_file) — no raw_io
        assert not violations, f"Unexpected violations: {violations}"


# ---------------------------------------------------------------------------
# Issue policy
# ---------------------------------------------------------------------------

class TestCommitPolicy:
    def test_valid_commit_with_issue(self):
        msg = "feat: add thing\n\nrad:72fb420abc1234567890abcdef123456789012"
        assert check_commit_message(msg) == []

    def test_short_hash_accepted(self):
        msg = "fix: bug\n\nrad:72fb420"
        assert check_commit_message(msg) == []

    def test_merge_commit_exempt(self):
        msg = "Merge branch 'main' into feat/x"
        assert check_commit_message(msg) == []

    def test_revert_commit_exempt(self):
        msg = "Revert \"feat: something\""
        assert check_commit_message(msg) == []

    def test_missing_issue_fails(self):
        msg = "fix: something without an issue"
        violations = check_commit_message(msg)
        assert len(violations) == 1
        assert violations[0].rule == "issue_policy"

    def test_comment_lines_ignored(self):
        msg = "fix: thing\n# rad:72fb420 this is a comment\nno issue ref"
        violations = check_commit_message(msg)
        assert "issue_policy" in {v.rule for v in violations}


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

class TestScore:
    def test_no_violations_is_100(self):
        assert score([]) == 100

    def test_one_error_deducts_15(self):
        v = Violation(rule="raw_io", severity="error", message="x")
        assert score([v]) == 85

    def test_one_warning_deducts_5(self):
        v = Violation(rule="missing_category", severity="warning", message="x")
        assert score([v]) == 95

    def test_score_floors_at_zero(self):
        errors = [Violation(rule="raw_io", severity="error", message="x")] * 10
        assert score(errors) == 0


# ---------------------------------------------------------------------------
# Capability round-trips
# ---------------------------------------------------------------------------

class TestConformanceCapabilities:
    def test_capabilities_registered(self):
        host = _make_host()
        caps = set(host._capabilities.keys())
        assert any("check_source" in k for k in caps)
        assert any("check_adapter" in k for k in caps)
        assert any("check_all" in k for k in caps)
        assert any("policy_check" in k for k in caps)
        assert any("open_dev_session" in k for k in caps)
        assert any("check_staged" in k for k in caps)
        assert any("close_dev_session" in k for k in caps)
        assert any("report_violations" in k for k in caps)

    def test_policy_check_via_capability(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.conformance.policy_check", {
            "commit_message": "feat: thing\n\nrad:72fb420"
        })
        assert r.success
        assert r.data["passes"] is True

    def test_policy_check_fails_without_issue(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.conformance.policy_check", {
            "commit_message": "feat: thing without issue"
        })
        assert r.success
        assert r.data["passes"] is False

    def test_check_source_via_capability(self, tmp_path):
        src = _src("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    open("/tmp/foo")
                    ctx.emit("done", {})
                    return {}
        """, tmp_path)
        host = _make_host()
        r = _invoke(host, "chp.adapters.conformance.check_source", {
            "source_path": str(src)
        })
        assert r.success
        assert r.data["violation_count"] >= 1
        assert r.data["score"] < 100

    def test_check_all_via_capability(self):
        host = _make_host()
        r = _invoke(host, "chp.adapters.conformance.check_all")
        assert r.success
        assert r.data["adapter_count"] >= 1

    def test_check_staged_no_session_raises(self, tmp_path):
        """check_staged raises if no active session file exists."""
        import json
        from pathlib import Path
        session = Path.home() / ".chp" / "active-session.json"
        existed = session.exists()
        backup = session.read_text() if existed else None
        if existed:
            session.unlink()
        try:
            host = _make_host()
            r = _invoke(host, "chp.adapters.conformance.check_staged", {"staged_files": []})
            assert not r.success or "No active dev session" in str(r.error)
        finally:
            if backup is not None:
                session.write_text(backup)

    def test_check_staged_empty_files_is_ok(self, tmp_path):
        """check_staged with no staged files returns ok=True."""
        import json
        from pathlib import Path
        session = Path.home() / ".chp" / "active-session.json"
        existed = session.exists()
        backup = session.read_text() if existed else None
        session.parent.mkdir(parents=True, exist_ok=True)
        session.write_text(json.dumps({
            "issue_id": "test0001",
            "baseline": {"adapters": [], "adapter_count": 0, "total_violations": 0},
        }))
        try:
            host = _make_host()
            r = _invoke(host, "chp.adapters.conformance.check_staged", {"staged_files": []})
            assert r.success
            assert r.data["ok"] is True
            assert r.data["new_violations"] == []
        finally:
            if backup is not None:
                session.write_text(backup)
            elif session.exists():
                session.unlink()

    def test_check_staged_detects_new_violation(self, tmp_path):
        """check_staged flags violations in staged files that aren't in baseline."""
        import json
        from pathlib import Path
        # Write a Python file with a raw_io violation
        bad_file = tmp_path / "bad_adapter.py"
        bad_file.write_text(textwrap.dedent("""
            from chp_core import capability

            class Adapter:
                @capability(id="x.y", version="1.0.0", input_schema={"type":"object","properties":{}})
                async def my_cap(self, ctx, payload):
                    open("/tmp/foo")
                    ctx.emit("done", {})
                    return {}
        """))
        session = Path.home() / ".chp" / "active-session.json"
        existed = session.exists()
        backup = session.read_text() if existed else None
        session.parent.mkdir(parents=True, exist_ok=True)
        session.write_text(json.dumps({
            "issue_id": "test0001",
            "baseline": {"adapters": [], "adapter_count": 0, "total_violations": 0},
        }))
        try:
            host = _make_host()
            r = _invoke(host, "chp.adapters.conformance.check_staged", {
                "staged_files": [str(bad_file)],
            })
            assert r.success
            assert r.data["ok"] is False
            rules = {v["rule"] for v in r.data["new_violations"]}
            assert "raw_io" in rules
        finally:
            if backup is not None:
                session.write_text(backup)
            elif session.exists():
                session.unlink()


def test_session_file_keying():
    """repo_path-keyed sessions: global default, deterministic + distinct keyed files."""
    from chp_adapter_conformance import adapter as A
    assert A._session_file(None) == A._SESSION_FILE
    f1, f2, f3 = A._session_file("/a/repo"), A._session_file("/a/repo"), A._session_file("/b/repo")
    assert f1 == f2 and f1 != f3
    assert f1.parent == A._SESSION_DIR


def test_resolve_existing_falls_back_to_global():
    """A keyed path with no keyed file resolves to the global session file."""
    from chp_adapter_conformance import adapter as A
    # An unlikely path that has no keyed session file → fall back to global.
    assert A._resolve_existing("/no/such/worktree/xyzzy") == A._SESSION_FILE
