"""Tests for RadicleAdapter.

All tests use FakeRadicleBackend — no real ``rad`` binary required.
"""

from __future__ import annotations

import pytest
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_radicle import FakeRadicleBackend, RadicleAdapter, RadicleConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host(backend: FakeRadicleBackend, repo_path: str = "/fake/repo") -> LocalCapabilityHost:
    config = RadicleConfig(default_repo_path=repo_path, backend=backend)
    adapter = RadicleAdapter(config=config)
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _domain_events(host: LocalCapabilityHost) -> list[dict]:
    return [e for e in host.store.all() if "capability_uri" not in e.get("payload", {})]


_RAD_INSPECT = """\
rad:z44Jkxv3MxhdeegnPcBrCC2nr2Zfn

Name        chp-dev
Description Private dev repo
Visibility  private
Delegates   z6Mku... (2)
"""

_RAD_LS = """\
z44Jkxv3  chp-dev    private
z74KDU7f  chp-agent  private
"""

_RAD_SELF = """\
DID  did:key:z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn
NID  z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn
"""

_RAD_NODE_STATUS = "Running   z6Mku... connected: 3"

_RAD_PATCH_LIST = """\
5eaeae9 open  feat(adapters): add 20 packages  feat/chp-v0.1-foundation
abc1234 open  fix(router): failover test  feat/multi-host
"""

_RAD_ISSUE_LIST = """\
cafe123 open  Transport conformance gap
beef456 open  Add Radicle adapter
"""

_RAD_ISSUE_SHOW = """\
Title   Add Radicle adapter
State   open
Labels  enhancement
2 comments
"""

SECRET_ISSUE_BODY = "SECRET_ISSUE_BODY_TEXT"
SECRET_PATCH_BODY = "SECRET_PATCH_BODY_CONTENT"
SECRET_NID = "z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn"
SECRET_COMMENT = "SECRET_COMMENT_TEXT_INTERNAL"


# ---------------------------------------------------------------------------
# repo_info
# ---------------------------------------------------------------------------

class TestRepoInfo:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(responses={("inspect",): _RAD_INSPECT})

    @pytest.mark.asyncio
    async def test_rid_extracted(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {})
        assert result.data["rid"] == "rad:z44Jkxv3MxhdeegnPcBrCC2nr2Zfn"

    @pytest.mark.asyncio
    async def test_name_extracted(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {})
        assert result.data["name"] == "chp-dev"

    @pytest.mark.asyncio
    async def test_visibility_extracted(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {})
        assert result.data["visibility"] == "private"

    @pytest.mark.asyncio
    async def test_delegate_count(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {})
        assert result.data["delegate_count"] == 2

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        backend = FakeRadicleBackend()
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {"unknown": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_error_propagates(self):
        class ErrorBackend(FakeRadicleBackend):
            def run(self, *args, cwd=None):
                raise RuntimeError("not a radicle repo")
        host = _make_host(ErrorBackend())
        result = await host.ainvoke("chp.adapters.radicle.repo_info", {})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# list_repos
# ---------------------------------------------------------------------------

class TestListRepos:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(responses={("ls",): _RAD_LS})

    @pytest.mark.asyncio
    async def test_repos_returned(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.list_repos", {})
        assert result.data["count"] == 2

    @pytest.mark.asyncio
    async def test_repo_names(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.list_repos", {})
        names = [r["name"] for r in result.data["repos"]]
        assert "chp-dev" in names
        assert "chp-agent" in names

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.list_repos", {"x": 1})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# identity — NID never in evidence
# ---------------------------------------------------------------------------

class TestIdentity:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(responses={("self",): _RAD_SELF})

    @pytest.mark.asyncio
    async def test_did_returned(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.identity", {})
        assert result.data["did"].startswith("did:key:")

    @pytest.mark.asyncio
    async def test_nid_not_in_result(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.identity", {})
        assert "nid" not in result.data

    @pytest.mark.asyncio
    async def test_nid_not_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.identity", {})
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_NID not in dump


# ---------------------------------------------------------------------------
# node_status
# ---------------------------------------------------------------------------

class TestNodeStatus:
    @pytest.mark.asyncio
    async def test_running_parsed(self):
        backend = FakeRadicleBackend(responses={("node", "status"): _RAD_NODE_STATUS})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.node_status", {})
        assert result.data["running"] is True
        assert result.data["peers"] == 3

    @pytest.mark.asyncio
    async def test_stopped_when_empty(self):
        backend = FakeRadicleBackend(responses={("node", "status"): "Node is not running"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.node_status", {})
        assert result.data["running"] is False


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

class TestSync:
    @pytest.mark.asyncio
    async def test_sync_ok(self):
        backend = FakeRadicleBackend(responses={("sync",): "✓ Synced 1 repo to 2 seeds"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.sync", {})
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_sync_error_in_message(self):
        backend = FakeRadicleBackend(responses={("sync",): "✗ Error: no seeds found"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.sync", {})
        assert result.data["ok"] is False


# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------

class TestPush:
    @pytest.mark.asyncio
    async def test_push_records_branch(self):
        backend = FakeRadicleBackend(
            push_responses={("rad", "feat/my-branch"): "✓ Patch abc1234 updated to revision def5678\nTo rad://z44Jkxv3"}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.push", {"branch": "feat/my-branch"})
        assert result.data["branch"] == "feat/my-branch"
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_push_extracts_patch_id(self):
        backend = FakeRadicleBackend(
            push_responses={("rad", "feat/my-branch"): "✓ Patch abc1234 updated to revision def5678"}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.push", {"branch": "feat/my-branch"})
        assert result.data["patch_id"] == "abc1234"

    @pytest.mark.asyncio
    async def test_push_branch_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.push", {})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# patch_list
# ---------------------------------------------------------------------------

class TestPatchList:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(responses={("patch", "list"): _RAD_PATCH_LIST})

    @pytest.mark.asyncio
    async def test_patches_returned(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_list", {})
        assert result.data["count"] == 2

    @pytest.mark.asyncio
    async def test_patch_ids_present(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_list", {})
        ids = [p["id"] for p in result.data["patches"]]
        assert "5eaeae9" in ids

    @pytest.mark.asyncio
    async def test_patch_body_not_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.patch_list", {})
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_PATCH_BODY not in dump


# ---------------------------------------------------------------------------
# patch_open — body never in evidence
# ---------------------------------------------------------------------------

class TestPatchOpen:
    @pytest.mark.asyncio
    async def test_patch_id_extracted(self):
        backend = FakeRadicleBackend(
            responses={("patch", "open", "--title", "My Patch", "--base", "master", "--no-edit"): "✓ Opened patch abc1234"}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_open", {"title": "My Patch"})
        assert result.data["patch_id"] == "abc1234"
        assert result.data["title"] == "My Patch"

    @pytest.mark.asyncio
    async def test_patch_body_not_in_evidence(self):
        backend = FakeRadicleBackend(
            responses={("patch", "open", "--title", "Test", "--base", "master", "--no-edit"): "abc1234"}
        )
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.patch_open", {"title": "Test", "body": SECRET_PATCH_BODY})
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_PATCH_BODY not in dump

    @pytest.mark.asyncio
    async def test_title_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_open", {})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# issue_list
# ---------------------------------------------------------------------------

class TestIssueList:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(responses={("issue", "list", "--state", "open"): _RAD_ISSUE_LIST})

    @pytest.mark.asyncio
    async def test_issues_returned(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_list", {})
        assert result.data["count"] == 2

    @pytest.mark.asyncio
    async def test_issue_ids_present(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_list", {})
        ids = [i["id"] for i in result.data["issues"]]
        assert "cafe123" in ids

    @pytest.mark.asyncio
    async def test_issue_body_not_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.issue_list", {})
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_ISSUE_BODY not in dump

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_list", {"bad": True})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# issue_show — body never in evidence
# ---------------------------------------------------------------------------

class TestIssueShow:
    @pytest.fixture
    def backend(self):
        return FakeRadicleBackend(
            responses={("issue", "show", "beef456"): _RAD_ISSUE_SHOW + f"\n{SECRET_ISSUE_BODY}"}
        )

    @pytest.mark.asyncio
    async def test_title_and_state(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_show", {"issue_id": "beef456"})
        assert result.data["title"] == "Add Radicle adapter"
        assert result.data["state"] == "open"

    @pytest.mark.asyncio
    async def test_comment_count(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_show", {"issue_id": "beef456"})
        assert result.data["comment_count"] == 2

    @pytest.mark.asyncio
    async def test_body_not_in_evidence(self, backend):
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.issue_show", {"issue_id": "beef456"})
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_ISSUE_BODY not in dump


# ---------------------------------------------------------------------------
# issue_comment — comment text never in evidence
# ---------------------------------------------------------------------------

class TestIssueComment:
    @pytest.mark.asyncio
    async def test_posted_true(self):
        backend = FakeRadicleBackend(
            responses={("issue", "comment", "cafe123", "-m", SECRET_COMMENT): ""}
        )
        host = _make_host(backend)
        result = await host.ainvoke(
            "chp.adapters.radicle.issue_comment",
            {"issue_id": "cafe123", "message": SECRET_COMMENT},
        )
        assert result.data["posted"] is True

    @pytest.mark.asyncio
    async def test_comment_text_not_in_evidence(self):
        backend = FakeRadicleBackend(
            responses={("issue", "comment", "cafe123", "-m", SECRET_COMMENT): ""}
        )
        host = _make_host(backend)
        await host.ainvoke(
            "chp.adapters.radicle.issue_comment",
            {"issue_id": "cafe123", "message": SECRET_COMMENT},
        )
        evs = _domain_events(host)
        dump = str(evs)
        assert SECRET_COMMENT not in dump

    @pytest.mark.asyncio
    async def test_issue_id_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_comment", {"message": "hi"})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# issue_close
# ---------------------------------------------------------------------------

class TestIssueClose:
    @pytest.mark.asyncio
    async def test_closed_true(self):
        backend = FakeRadicleBackend(
            responses={("issue", "close", "cafe123"): ""}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_close", {"issue_id": "cafe123"})
        assert result.data["closed"] is True

    @pytest.mark.asyncio
    async def test_issue_id_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_close", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_error_propagates(self):
        class ErrorBackend(FakeRadicleBackend):
            def run(self, *args, cwd=None):
                raise RuntimeError("issue not found")
        host = _make_host(ErrorBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_close", {"issue_id": "bad"})
        assert result.outcome == "failure"


class TestIssueOpen:
    @pytest.mark.asyncio
    async def test_issue_id_extracted(self):
        backend = FakeRadicleBackend(
            responses={("issue", "open", "--title", "My Issue", "--no-edit"): "✓ Opened issue abc1234"}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_open", {"title": "My Issue"})
        assert result.outcome == "success"
        assert result.data["issue_id"] == "abc1234"
        assert result.data["title"] == "My Issue"

    @pytest.mark.asyncio
    async def test_body_not_in_evidence(self):
        backend = FakeRadicleBackend(
            responses={
                ("issue", "open", "--title", "T", "--no-edit", "--description", SECRET_ISSUE_BODY): "opened abc1234"
            }
        )
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.radicle.issue_open", {"title": "T", "body": SECRET_ISSUE_BODY})
        dump = str([e["payload"] for e in _domain_events(host)])
        assert SECRET_ISSUE_BODY not in dump

    @pytest.mark.asyncio
    async def test_labels_passed_to_backend(self):
        backend = FakeRadicleBackend(
            responses={
                ("issue", "open", "--title", "T", "--no-edit", "--labels", "bug,p1"): "opened abc1234"
            }
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_open", {"title": "T", "labels": ["bug", "p1"]})
        assert result.outcome == "success"
        assert ("issue", "open", "--title", "T", "--no-edit", "--labels", "bug,p1") in backend.calls

    @pytest.mark.asyncio
    async def test_title_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_open", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_extra_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_open", {"title": "T", "unknown": "x"})
        assert result.outcome == "denied"

    def test_shaping(self):
        ids = {c.descriptor.id for c in RadicleAdapter().capabilities()}
        assert "chp.adapters.radicle.issue_open" in ids
