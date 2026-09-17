"""git.commit_reconcile — verdict-returning reconciliation READ (rad:8f4b6a0), and
mutating caps declare side_effects (so a bare host does not auto-ALLOW them)."""

from __future__ import annotations

import subprocess

import pytest
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_git import GitAdapter, GitConfig


def _real_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@t.dev"],
                ["git", "config", "user.name", "t"]):
        subprocess.run(cmd, cwd=repo, check=True)
    (repo / "a.txt").write_text("hi\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fix: landed commit"], cwd=repo, check=True)
    return repo


def _host(repo):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, GitAdapter(config=GitConfig(default_repo_path=str(repo))))
    return host


class TestCommitReconcile:
    def test_succeeded_when_commit_present(self, tmp_path):
        host = _host(_real_repo(tmp_path))
        r = host.invoke("chp.adapters.git.commit_reconcile", {"message": "fix: landed commit"})
        assert r.success
        assert r.data["outcome"] == "SUCCEEDED"
        assert r.data["result"]["sha7"]

    def test_not_found_when_absent(self, tmp_path):
        host = _host(_real_repo(tmp_path))
        r = host.invoke("chp.adapters.git.commit_reconcile", {"message": "fix: never happened"})
        assert r.success
        assert r.data["outcome"] == "NOT_FOUND"

    def test_reconcile_is_read_only_no_side_effects(self, tmp_path):
        host = _host(_real_repo(tmp_path))
        desc = host._capabilities["chp.adapters.git.commit_reconcile:0.1.0"].descriptor
        assert desc.side_effects == []  # a READ verdict — no mutation


class TestMutatingCapsDeclareSideEffects:
    @pytest.mark.parametrize("cap", ["commit", "checkout_branch", "clone", "init", "push", "pull"])
    def test_mutation_has_side_effects(self, tmp_path, cap):
        host = _host(_real_repo(tmp_path))
        desc = host._capabilities[f"chp.adapters.git.{cap}:0.1.0"].descriptor
        # non-empty side_effects => a bare host classifies it as a mutation, never auto-ALLOW
        assert desc.side_effects, f"{cap} must declare side_effects"
