"""Tests for GitAdapter.

All tests use FakeGitBackend — no real git repository required.
"""

from __future__ import annotations

import pytest
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_git import GitAdapter, GitConfig, SubprocessGitBackend


# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------

class FakeGitBackend:
    """Records calls and returns scripted responses."""

    def __init__(self, responses: dict[tuple, str] | None = None, default: str = "") -> None:
        self._responses = responses or {}
        self._default = default
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str, cwd: str | None = None) -> str:
        self.calls.append(args)
        return self._responses.get(args, self._default)


def _make_host(backend: FakeGitBackend, repo_path: str = "/fake/repo") -> LocalCapabilityHost:
    config = GitConfig(default_repo_path=repo_path, backend=backend)
    adapter = GitAdapter(config=config)
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _domain_events(host: LocalCapabilityHost) -> list[dict]:
    return [e for e in host.store.all() if "capability_uri" not in e.get("payload", {})]


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("rev-parse", "--abbrev-ref", "HEAD"): "main",
            ("status", "--porcelain"): "M  src/foo.py\n?? scratch.txt\n M src/bar.py",
        })

    @pytest.mark.asyncio
    async def test_branch_returned(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {})
        assert result.data["branch"] == "main"

    @pytest.mark.asyncio
    async def test_counts_staged_unstaged_untracked(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {})
        out = result.data
        assert out["staged"] >= 1
        assert out["untracked"] == 1

    @pytest.mark.asyncio
    async def test_clean_repo(self):
        backend = FakeGitBackend(responses={
            ("rev-parse", "--abbrev-ref", "HEAD"): "main",
            ("status", "--porcelain"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {})
        assert result.data["clean"] is True

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        backend = FakeGitBackend()
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {"unknown": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_repo_path_override(self):
        backend = FakeGitBackend(responses={
            ("rev-parse", "--abbrev-ref", "HEAD"): "feature",
            ("status", "--porcelain"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {"repo_path": "/other/repo"})
        assert result.data["branch"] == "feature"

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("not a git repo")

        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.status", {})
        assert result.outcome == "failure"

    @pytest.mark.asyncio
    async def test_evidence_emitted(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.git.status", {})
        evs = _domain_events(host)
        event_types = [e["event_type"] for e in evs]
        assert "git_request" in event_types
        assert "git_response" in event_types

    @pytest.mark.asyncio
    async def test_outcome_success(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.status", {})
        assert result.outcome == "success"


# ---------------------------------------------------------------------------
# inspect_repo
# ---------------------------------------------------------------------------

_SHA = "abc1234567890abcdef1234567890abcdef12345"

class TestInspectRepo:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("rev-parse", "--abbrev-ref", "HEAD"): "main",
            ("rev-parse", "HEAD"): _SHA,
            ("remote", "-v"): "origin\thttps://github.com/org/repo.git (fetch)\norigin\thttps://github.com/org/repo.git (push)",
            ("rev-list", "--count", "HEAD"): "42",
        })

    @pytest.mark.asyncio
    async def test_basic_fields(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.inspect_repo", {})
        out = result.data
        assert out["branch"] == "main"
        assert out["head_sha7"] == _SHA[:7]
        assert out["head_sha"] == _SHA[:40]
        assert out["commit_count"] == 42
        assert "origin" in out["remotes"]

    @pytest.mark.asyncio
    async def test_no_remotes(self):
        backend = FakeGitBackend(responses={
            ("rev-parse", "--abbrev-ref", "HEAD"): "main",
            ("rev-parse", "HEAD"): _SHA,
            ("remote", "-v"): "",
            ("rev-list", "--count", "HEAD"): "1",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.inspect_repo", {})
        assert result.data["remotes"] == []

    @pytest.mark.asyncio
    async def test_deduplicates_remotes(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.inspect_repo", {})
        assert result.data["remotes"].count("origin") == 1

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.inspect_repo", {"secret": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_outcome_success(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.inspect_repo", {})
        assert result.outcome == "success"


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------

_SEP = "\x1f"
_REC = "\x00"  # records are NUL-separated: a commit body is multi-line, so lines can't delimit them
# git writes the format then a newline, hence the trailing "\n" after each record.
_LOG_OUTPUT = "".join([
    f"abc1234{_SEP}Alice{_SEP}2024-01-01T00:00:00+00:00{_SEP}Initial commit{_REC}\n",
    f"def5678{_SEP}Bob{_SEP}2024-01-02T00:00:00+00:00{_SEP}Add feature{_REC}\n",
])


def _fmt(include_body: bool = False) -> str:
    # `%x00` is git's ESCAPE for NUL, expanded by git itself. A literal NUL cannot be passed in argv
    # (execve strings are NUL-terminated) — the OS would truncate the format and every commit would
    # come back unparsed. A mock that encodes a literal NUL here would pass while real git fails.
    return f"%h{_SEP}%an{_SEP}%aI{_SEP}%s" + (f"{_SEP}%b" if include_body else "") + "%x00"


def _log_backend(limit: int = 20, branch: str = "HEAD") -> FakeGitBackend:
    return FakeGitBackend(responses={
        ("log", f"-{limit}", f"--format={_fmt()}", branch): _LOG_OUTPUT,
    })


class TestLog:
    @pytest.mark.asyncio
    async def test_returns_commits(self):
        host = _make_host(_log_backend())
        result = await host.ainvoke("chp.adapters.git.log", {})
        assert result.outcome == "success"
        assert result.data["count"] == 2
        assert result.data["commits"][0]["sha7"] == "abc1234"
        assert result.data["commits"][0]["author"] == "Alice"

    @pytest.mark.asyncio
    async def test_subject_truncated_to_80_chars(self):
        long_subject = "A" * 100
        backend = FakeGitBackend(responses={
            ("log", "-20", f"--format={_fmt()}", "HEAD"): f"aaa1111{_SEP}Dev{_SEP}2024-01-01T00:00:00+00:00{_SEP}{long_subject}{_REC}\n",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.log", {})
        assert len(result.data["commits"][0]["subject"]) == 80

    @pytest.mark.asyncio
    async def test_include_body_survives_a_multiline_body(self):
        """A body is multi-line. Line-delimited records would swallow its first line into `subject`
        and silently drop the rest — no exception, just quietly wrong data. Records are NUL-delimited
        precisely so a body can contain anything a human types."""
        body = "Fixes issue-1234.\n\nSecond paragraph.\nRef: 7f3a2b1"
        backend = FakeGitBackend(responses={
            ("log", "-20", f"--format={_fmt(True)}", "HEAD"):
                f"abc1234{_SEP}Alice{_SEP}2024-01-01T00:00:00+00:00{_SEP}fix: a thing{_SEP}{body}{_REC}\n"
                f"def5678{_SEP}Bob{_SEP}2024-01-02T00:00:00+00:00{_SEP}chore: another{_SEP}no trailer here{_REC}\n",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.log", {"include_body": True})
        commits = result.data["commits"]
        assert result.data["count"] == 2                      # the multi-line body did NOT split records
        assert commits[0]["subject"] == "fix: a thing"        # body did not bleed into subject
        assert "issue-1234" in commits[0]["body"]
        assert "Ref: 7f3a2b1" in commits[0]["body"]           # the LAST line survived
        assert commits[1]["body"] == "no trailer here"

    @pytest.mark.asyncio
    async def test_body_is_absent_unless_asked(self):
        host = _make_host(_log_backend())
        result = await host.ainvoke("chp.adapters.git.log", {})
        assert "body" not in result.data["commits"][0]        # additive: default shape unchanged

    @pytest.mark.asyncio
    async def test_custom_limit(self):
        host = _make_host(_log_backend(limit=5))
        result = await host.ainvoke("chp.adapters.git.log", {"limit": 5})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_limit_capped_at_max(self):
        backend = FakeGitBackend(responses={
            ("log", "-10", f"--format={_fmt()}", "HEAD"): _LOG_OUTPUT,
        })
        # max_log_entries=10; passing limit=80 (valid per schema) should cap to 10
        config = GitConfig(default_repo_path="/fake", backend=backend, max_log_entries=10)
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.log", {"limit": 80})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(_log_backend())
        result = await host.ainvoke("chp.adapters.git.log", {"secret": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_custom_branch(self):
        host = _make_host(_log_backend(branch="feature"))
        result = await host.ainvoke("chp.adapters.git.log", {"branch": "feature"})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_evidence_count_not_content(self):
        host = _make_host(_log_backend())
        await host.ainvoke("chp.adapters.git.log", {})
        evs = _domain_events(host)
        response_ev = next(e for e in evs if e["event_type"] == "git_response")
        assert "commits" not in response_ev["payload"]
        assert "count" in response_ev["payload"]


# ---------------------------------------------------------------------------
# diff_summary
# ---------------------------------------------------------------------------

_STAT_OUTPUT = "src/foo.py | 10 +++++-----\nsrc/bar.py |  5 +++++\n"
_SHORT_OUTPUT = " 2 files changed, 15 insertions(+), 5 deletions(-)"


class TestDiffSummary:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("diff", "--stat"): _STAT_OUTPUT,
            ("diff", "--shortstat"): _SHORT_OUTPUT,
        })

    @pytest.mark.asyncio
    async def test_counts_parsed(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {})
        out = result.data
        assert out["files_changed"] == 2
        assert out["insertions"] == 15
        assert out["deletions"] == 5

    @pytest.mark.asyncio
    async def test_changed_files_listed(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {})
        assert "src/foo.py" in result.data["changed_files"]
        assert "src/bar.py" in result.data["changed_files"]

    @pytest.mark.asyncio
    async def test_staged_flag(self):
        backend = FakeGitBackend(responses={
            ("diff", "--stat", "--cached"): _STAT_OUTPUT,
            ("diff", "--shortstat", "--cached"): _SHORT_OUTPUT,
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {"staged": True})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_base_ref(self):
        backend = FakeGitBackend(responses={
            ("diff", "--stat", "main"): _STAT_OUTPUT,
            ("diff", "--shortstat", "main"): _SHORT_OUTPUT,
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {"base": "main"})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_empty_diff(self):
        backend = FakeGitBackend(responses={
            ("diff", "--stat"): "",
            ("diff", "--shortstat"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {})
        assert result.data["files_changed"] == 0
        assert result.data["insertions"] == 0

    @pytest.mark.asyncio
    async def test_no_patch_text_in_output(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {})
        # diff_summary must NOT include patch text
        output_str = str(result.data)
        assert "+++++-----" not in output_str

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.diff_summary", {"patch": True})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# precommit_check
# ---------------------------------------------------------------------------

class TestPrecommitCheck:
    @pytest.fixture
    def backend(self):
        # M  staged modified; " M" unstaged modified; ?? untracked
        return FakeGitBackend(responses={
            ("status", "--porcelain"): "M  src/a.py\n M src/b.py\n?? scratch.txt",
        })

    @pytest.mark.asyncio
    async def test_staged_files_listed(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert "src/a.py" in result.data["staged_files"]

    @pytest.mark.asyncio
    async def test_unstaged_count(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["unstaged_count"] == 1

    @pytest.mark.asyncio
    async def test_untracked_count(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["untracked_count"] == 1

    @pytest.mark.asyncio
    async def test_ready_to_commit_false_when_unstaged(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["ready_to_commit"] is False

    @pytest.mark.asyncio
    async def test_ready_to_commit_true_when_only_staged(self):
        backend = FakeGitBackend(responses={
            ("status", "--porcelain"): "M  src/a.py",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["ready_to_commit"] is True

    @pytest.mark.asyncio
    async def test_no_staged_not_ready(self):
        backend = FakeGitBackend(responses={
            ("status", "--porcelain"): " M src/a.py",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["ready_to_commit"] is False

    @pytest.mark.asyncio
    async def test_clean_repo(self):
        backend = FakeGitBackend(responses={("status", "--porcelain"): ""})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {})
        assert result.data["staged_count"] == 0
        assert result.data["ready_to_commit"] is False

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.precommit_check", {"debug": True})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# checkout_branch
# ---------------------------------------------------------------------------

class TestCheckoutBranch:
    @pytest.fixture
    def backend_new(self):
        return FakeGitBackend(responses={
            ("branch", "--list", "feature"): "",
            ("checkout", "-b", "feature"): "",
            ("rev-parse", "--abbrev-ref", "HEAD"): "feature",
        })

    @pytest.fixture
    def backend_existing(self):
        return FakeGitBackend(responses={
            ("branch", "--list", "main"): "main",
            ("checkout", "main"): "",
            ("rev-parse", "--abbrev-ref", "HEAD"): "main",
        })

    @pytest.mark.asyncio
    async def test_creates_new_branch(self, backend_new):
        host = _make_host(backend_new)
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {"branch": "feature"})
        assert result.outcome == "success"
        assert result.data["branch"] == "feature"

    @pytest.mark.asyncio
    async def test_switches_to_existing_branch(self, backend_existing):
        host = _make_host(backend_existing)
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {"branch": "main"})
        assert result.outcome == "success"
        assert result.data["branch"] == "main"

    @pytest.mark.asyncio
    async def test_create_false_no_new(self):
        backend = FakeGitBackend(responses={
            ("checkout", "develop"): "",
            ("rev-parse", "--abbrev-ref", "HEAD"): "develop",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {"branch": "develop", "create": False})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_missing_branch_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {"branch": "x", "force": True})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("branch not found")

        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.checkout_branch", {"branch": "missing"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# commit
# ---------------------------------------------------------------------------

class TestCommit:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("add", "src/foo.py"): "",
            ("commit", "-m", "Add feature"): "[main abc1234] Add feature\n 1 file changed",
            ("rev-parse", "HEAD"): _SHA,
        })

    @pytest.fixture
    def backend_all(self):
        return FakeGitBackend(responses={
            ("add", "-u"): "",
            ("commit", "-m", "Fix bug"): "[main def5678] Fix bug",
            ("rev-parse", "HEAD"): _SHA,
        })

    @pytest.mark.asyncio
    async def test_commit_with_specific_file(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.commit", {
            "message": "Add feature",
            "files": ["src/foo.py"],
        })
        assert result.outcome == "success"
        assert result.data["sha7"] == _SHA[:7]
        assert result.data["files_staged"] == 1

    @pytest.mark.asyncio
    async def test_commit_all_tracked(self, backend_all):
        host = _make_host(backend_all)
        result = await host.ainvoke("chp.adapters.git.commit", {"message": "Fix bug"})
        assert result.outcome == "success"
        assert result.data["files_staged"] == 0  # no explicit files

    @pytest.mark.asyncio
    async def test_allow_empty_flag(self):
        backend = FakeGitBackend(responses={
            ("add", "-u"): "",
            ("commit", "-m", "Empty", "--allow-empty"): "[main aaa0000] Empty",
            ("rev-parse", "HEAD"): _SHA,
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.commit", {"message": "Empty", "allow_empty": True})
        assert result.outcome == "success"

    @pytest.mark.asyncio
    async def test_missing_message_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.commit", {"files": ["x.py"]})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.commit", {"message": "x", "author": "bob"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_commit_message_not_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.git.commit", {
            "message": "SECRET_COMMIT_MESSAGE",
            "files": ["src/foo.py"],
        })
        dump = str([e["payload"] for e in host.store.all()])
        assert "SECRET_COMMIT_MESSAGE" not in dump

    @pytest.mark.asyncio
    async def test_sha_in_output(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.commit", {
            "message": "Add feature",
            "files": ["src/foo.py"],
        })
        assert len(result.data["sha"]) == 40
        assert result.data["sha7"] == result.data["sha"][:7]

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("nothing to commit")

        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.commit", {"message": "test"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# SubprocessGitBackend smoke test
# ---------------------------------------------------------------------------

class TestSubprocessGitBackend:
    def test_is_instantiable(self):
        b = SubprocessGitBackend()
        assert isinstance(b, SubprocessGitBackend)

    def test_run_invalid_command_raises(self):
        b = SubprocessGitBackend()
        with pytest.raises(RuntimeError):
            b.run("log", "--invalid-flag-xyz", cwd="/tmp")


# ---------------------------------------------------------------------------
# Shaping — discover all 7 capabilities
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------

class TestPush:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("rev-parse", "HEAD"): _SHA,
            ("push", "origin", "main"): "",
        })

    @pytest.mark.asyncio
    async def test_push_succeeds(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.push", {"remote": "origin", "ref": "main"})
        assert result.outcome == "success"
        assert result.data["remote"] == "origin"
        assert result.data["ref"] == "main"
        assert result.data["head_sha7"] == _SHA[:7]
        assert result.data["success"] is True

    @pytest.mark.asyncio
    async def test_push_records_sha_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.git.push", {"remote": "origin", "ref": "main"})
        evs = _domain_events(host)
        resp = next(e for e in evs if e["event_type"] == "git_response")
        assert resp["payload"]["head_sha7"] == _SHA[:7]

    @pytest.mark.asyncio
    async def test_force_flag(self):
        backend = FakeGitBackend(responses={
            ("rev-parse", "HEAD"): _SHA,
            ("push", "origin", "main", "--force-with-lease"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.push", {"remote": "origin", "ref": "main", "force": True})
        assert result.outcome == "success"
        assert ("push", "origin", "main", "--force-with-lease") in backend.calls

    @pytest.mark.asyncio
    async def test_missing_remote_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.push", {"ref": "main"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_missing_ref_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.push", {"remote": "origin"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.push", {"remote": "origin", "ref": "main", "no_verify": True})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("rejected: non-fast-forward")
        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.push", {"remote": "origin", "ref": "main"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------

class TestPull:
    @pytest.fixture
    def backend_ff(self):
        return FakeGitBackend(responses={
            ("pull", "origin", "main"): "Updating abc1234..def5678\nFast-forward\n src/foo.py | 2 ++\n",
            ("rev-parse", "HEAD"): _SHA,
        })

    @pytest.fixture
    def backend_up_to_date(self):
        return FakeGitBackend(responses={
            ("pull", "origin"): "Already up to date.",
            ("rev-parse", "HEAD"): _SHA,
        })

    @pytest.mark.asyncio
    async def test_pull_with_branch(self, backend_ff):
        host = _make_host(backend_ff)
        result = await host.ainvoke("chp.adapters.git.pull", {"remote": "origin", "branch": "main"})
        assert result.outcome == "success"
        assert result.data["fast_forward"] is True
        assert result.data["head_sha7"] == _SHA[:7]

    @pytest.mark.asyncio
    async def test_pull_without_branch(self, backend_up_to_date):
        host = _make_host(backend_up_to_date)
        result = await host.ainvoke("chp.adapters.git.pull", {})
        assert result.outcome == "success"
        assert result.data["already_up_to_date"] is True
        assert result.data["fast_forward"] is False

    @pytest.mark.asyncio
    async def test_default_remote_is_origin(self, backend_up_to_date):
        host = _make_host(backend_up_to_date)
        result = await host.ainvoke("chp.adapters.git.pull", {})
        assert result.data["remote"] == "origin"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.pull", {"rebase": True})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_evidence_emitted(self, backend_ff):
        host = _make_host(backend_ff)
        await host.ainvoke("chp.adapters.git.pull", {"remote": "origin", "branch": "main"})
        evs = _domain_events(host)
        types = [e["event_type"] for e in evs]
        assert "git_request" in types
        assert "git_response" in types

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("Could not resolve hostname")
        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.pull", {})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------

class TestMerge:
    @pytest.fixture
    def backend(self):
        return FakeGitBackend(responses={
            ("merge", "feature"): "Updating abc..def\nFast-forward",
            ("rev-parse", "HEAD"): _SHA,
        })

    @pytest.mark.asyncio
    async def test_merge_default_strategy(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.merge", {"branch": "feature"})
        assert result.outcome == "success"
        assert result.data["branch"] == "feature"
        assert result.data["strategy"] == "default"
        assert result.data["conflicts"] is False
        assert result.data["head_sha7"] == _SHA[:7]

    @pytest.mark.asyncio
    async def test_merge_squash_strategy(self):
        backend = FakeGitBackend(responses={
            ("merge", "--squash", "feature"): "",
            ("rev-parse", "HEAD"): _SHA,
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.merge", {"branch": "feature", "strategy": "squash"})
        assert result.outcome == "success"
        assert result.data["strategy"] == "squash"
        assert ("merge", "--squash", "feature") in backend.calls

    @pytest.mark.asyncio
    async def test_merge_no_ff_strategy(self):
        backend = FakeGitBackend(responses={
            ("merge", "--no-ff", "feature"): "",
            ("rev-parse", "HEAD"): _SHA,
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.git.merge", {"branch": "feature", "strategy": "no-ff"})
        assert result.data["strategy"] == "no-ff"
        assert ("merge", "--no-ff", "feature") in backend.calls

    @pytest.mark.asyncio
    async def test_message_not_in_evidence(self):
        backend = FakeGitBackend(responses={
            ("merge", "-m", "SECRET_MESSAGE", "feature"): "",
            ("rev-parse", "HEAD"): _SHA,
        })
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.git.merge", {"branch": "feature", "message": "SECRET_MESSAGE"})
        dump = str([e["payload"] for e in host.store.all()])
        assert "SECRET_MESSAGE" not in dump

    @pytest.mark.asyncio
    async def test_missing_branch_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.merge", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeGitBackend())
        result = await host.ainvoke("chp.adapters.git.merge", {"branch": "feature", "theirs": True})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_git_error_propagates(self):
        class ErrorBackend:
            def run(self, *args, cwd=None):
                raise RuntimeError("CONFLICT (content): Merge conflict in src/foo.py")
        config = GitConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = GitAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.git.merge", {"branch": "feature"})
        assert result.outcome == "failure"

    @pytest.mark.asyncio
    async def test_evidence_emitted(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.git.merge", {"branch": "feature"})
        evs = _domain_events(host)
        types = [e["event_type"] for e in evs]
        assert "git_request" in types
        assert "git_response" in types


# ---------------------------------------------------------------------------
# Shaping
# ---------------------------------------------------------------------------

class TestShaping:
    def test_ten_capabilities_registered(self):
        adapter = GitAdapter()
        caps = list(adapter.capabilities())
        ids = {c.descriptor.id for c in caps}
        assert "chp.adapters.git.status" in ids
        assert "chp.adapters.git.inspect_repo" in ids
        assert "chp.adapters.git.log" in ids
        assert "chp.adapters.git.diff_summary" in ids
        assert "chp.adapters.git.precommit_check" in ids
        assert "chp.adapters.git.checkout_branch" in ids
        assert "chp.adapters.git.commit" in ids
        assert "chp.adapters.git.push" in ids
        assert "chp.adapters.git.pull" in ids
        assert "chp.adapters.git.merge" in ids
        assert len(ids) == 10

    def test_low_risk_read_capabilities(self):
        adapter = GitAdapter()
        caps = {c.descriptor.id: c.descriptor for c in adapter.capabilities()}
        low_risk = {"chp.adapters.git.status", "chp.adapters.git.inspect_repo",
                    "chp.adapters.git.log", "chp.adapters.git.diff_summary",
                    "chp.adapters.git.precommit_check"}
        for cap_id in low_risk:
            assert caps[cap_id].risk == "low", f"{cap_id} should be low risk"

    def test_medium_risk_capabilities(self):
        adapter = GitAdapter()
        caps = {c.descriptor.id: c.descriptor for c in adapter.capabilities()}
        for cap_id in ("chp.adapters.git.checkout_branch", "chp.adapters.git.commit",
                       "chp.adapters.git.pull"):
            assert caps[cap_id].risk == "medium", f"{cap_id} should be medium risk"

    def test_high_risk_transport_capabilities(self):
        adapter = GitAdapter()
        caps = {c.descriptor.id: c.descriptor for c in adapter.capabilities()}
        for cap_id in ("chp.adapters.git.push", "chp.adapters.git.merge"):
            assert caps[cap_id].risk == "high", f"{cap_id} should be high risk"

    def test_all_schemas_have_additional_properties_false(self):
        adapter = GitAdapter()
        for cap in adapter.capabilities():
            schema = cap.descriptor.input_schema
            assert schema.get("additionalProperties") is False, \
                f"{cap.descriptor.id} missing additionalProperties: false"
