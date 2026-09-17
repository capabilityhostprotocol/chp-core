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

# rad 1.9.1 `rad patch list` box table (open patches marked ●; the parser takes ● rows).
_RAD_PATCH_LIST = """\
╭────────────────────────────────────────────────────────────────────────────╮
│ ●  ID       Title                             Author              Reviews  Head     +    -   Updated     │
├────────────────────────────────────────────────────────────────────────────┤
│ ●  5eaeae9  feat(adapters): add 20 packages   macbook-pro  (you)  -        a7d2390  +10  -0  1 hour ago  │
│ ●  abc1234  fix(router): failover test        macbook-pro  (you)  -        b1c2d3e  +5   -1  2 hours ago │
╰────────────────────────────────────────────────────────────────────────────╯
"""

def _issue_table(rows: list[tuple[str, str, str]]) -> str:
    """Build an aligned box-table like ``rad issue list`` (fixed-width columns)."""
    w = {"id": 9, "title": 40, "author": 20, "labels": 24, "assignees": 10}
    hdr = (f"│ ●   {'ID':<{w['id']}} {'Title':<{w['title']}} {'Author':<{w['author']}} "
           f"{'Labels':<{w['labels']}} {'Assignees':<{w['assignees']}} Opened │")
    bar = len(hdr) - 2
    lines = ["╭" + "─" * bar + "╮", hdr, "├" + "─" * bar + "┤"]
    for iid, title, labels in rows:
        lines.append(f"│ ●   {iid:<{w['id']}} {title:<{w['title']}} {'macbook-pro (you)':<{w['author']}} "
                     f"{labels:<{w['labels']}} {'':<{w['assignees']}} 1 hour ago │")
    lines.append("╰" + "─" * bar + "╯")
    return "\n".join(lines)


_RAD_ISSUE_LIST = _issue_table([
    ("cafe123", "Transport conformance gap", "bug, transport"),
    ("beef456", "Add Radicle adapter", "approved-for-dev"),
])

# rad 1.9.1 `rad issue show` box table (key is "Status", not "State").
_RAD_ISSUE_SHOW = """\
╭────────────────────────────────────────────────╮
│ Title   Add Radicle adapter                    │
│ Issue   beef456beef456beef456beef456beef456beef │
│ Author  macbook-pro (you)                      │
│ Labels  enhancement                            │
│ Status  open                                   │
╰────────────────────────────────────────────────╯
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
    async def test_opens_patch_via_refs_patches(self):
        # rad 1.9.1 opens a patch by pushing HEAD to the magic refs/patches ref (verified live).
        backend = FakeRadicleBackend(git_responses={
            ("push", "rad", "HEAD:refs/patches"): "✓ Patch 2594c826a46af7d15e1e21668adbcd4848c7224b opened",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_open", {"title": "My Patch"})
        assert result.outcome == "success"
        assert result.data["patch_id"] == "2594c826a46af7d15e1e21668adbcd4848c7224b"
        assert result.data["ok"] is True
        assert ("push", "rad", "HEAD:refs/patches") in backend.git_calls

    @pytest.mark.asyncio
    async def test_title_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_open", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_push_failure_propagates(self):
        class ErrBackend(FakeRadicleBackend):
            def git(self, *args, cwd=None):
                self.git_calls.append(args)
                raise RuntimeError("no rad remote")
        host = _make_host(ErrBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_open", {"title": "x"})
        assert result.outcome == "failure"

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
        return FakeRadicleBackend(responses={("issue", "list", "--open"): _RAD_ISSUE_LIST})

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
    async def test_labels_extracted(self, backend):
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_list", {})
        by_id = {i["id"]: i for i in result.data["issues"]}
        assert by_id["cafe123"]["labels"] == ["bug", "transport"]
        assert by_id["beef456"]["labels"] == ["approved-for-dev"]

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
    async def test_labels_and_issue_id(self, backend):
        # issue_show returns {issue_id, title, state, labels} — rad 1.9.1 `issue show` has no
        # parseable comment count, so the impl does not expose one (was a stale 1.6.1 assertion).
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_show", {"issue_id": "beef456"})
        assert result.data["issue_id"] == "beef456"
        assert result.data["labels"] == "enhancement"

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
        # rad 1.9.1: --description makes it non-interactive (no --no-edit); defaults to the title.
        backend = FakeRadicleBackend(
            responses={("issue", "open", "--title", "My Issue", "--description", "My Issue"): "✓ Opened issue abc1234"}
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
        # rad 1.9.1 takes repeated --labels flags (one per label), not a comma-joined value.
        expected = ("issue", "open", "--title", "T", "--description", "T", "--labels", "bug", "--labels", "p1")
        backend = FakeRadicleBackend(responses={expected: "opened abc1234"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_open", {"title": "T", "labels": ["bug", "p1"]})
        assert result.outcome == "success"
        assert expected in backend.calls

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


# ---------------------------------------------------------------------------
# seeding / replication
# ---------------------------------------------------------------------------

_RAD_SEED_LIST = """\
╭────────────────────────────────────────────────────────────────────╮
│ Repository                          Name      Policy   Scope        │
├────────────────────────────────────────────────────────────────────┤
│ rad:z44Jkxv3MxhdeegnPcBrCC2nr2Zfn   chp-dev   allow    followed     │
╰────────────────────────────────────────────────────────────────────╯
"""


class TestSeeding:
    @pytest.mark.asyncio
    async def test_seed_policies_listed(self):
        backend = FakeRadicleBackend(responses={("seed",): _RAD_SEED_LIST})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.seed_policies", {})
        assert result.outcome != "denied"
        assert result.data["count"] >= 1

    @pytest.mark.asyncio
    async def test_seed_sets_policy(self):
        rid = "rad:z44Jkxv3MxhdeegnPcBrCC2nr2Zfn"
        backend = FakeRadicleBackend(
            responses={("seed", rid, "--scope", "followed"): "✓ Seeding policy updated"}
        )
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.seed", {"rid": rid})
        assert result.data["ok"] is True
        assert result.data["scope"] == "followed"
        assert ("seed", rid, "--scope", "followed") in backend.calls

    @pytest.mark.asyncio
    async def test_seed_scope_all(self):
        rid = "rad:zABC"
        backend = FakeRadicleBackend(responses={("seed", rid, "--scope", "all"): "✓ ok"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.seed", {"rid": rid, "scope": "all"})
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_unseed(self):
        rid = "rad:zABC"
        backend = FakeRadicleBackend(responses={("unseed", rid): "✓ removed"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.unseed", {"rid": rid})
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_follow_with_alias(self):
        nid = "z6MkvP5"
        backend = FakeRadicleBackend(responses={("follow", nid, "--alias", "nas"): "✓ following"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.follow", {"nid": nid, "alias": "nas"})
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_node_connect(self):
        nid = "z6MkvP5"
        backend = FakeRadicleBackend(responses={("node", "connect", f"{nid}@100.1.2.3:8776"): "✓ connected"})
        host = _make_host(backend)
        result = await host.ainvoke(
            "chp.adapters.radicle.node_connect", {"nid": nid, "address": "100.1.2.3:8776"}
        )
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_seed_requires_rid(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.seed", {})
        assert result.outcome == "denied"

    def test_shaping_includes_seed_caps(self):
        ids = {c.descriptor.id for c in RadicleAdapter().capabilities()}
        for cid in ("seed", "unseed", "seed_policies", "follow", "node_connect"):
            assert f"chp.adapters.radicle.{cid}" in ids


class TestIssueLabel:
    @pytest.mark.asyncio
    async def test_add_label(self):
        backend = FakeRadicleBackend(responses={("issue", "label", "cafe123", "--add", "approved-for-dev"): "ok"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_label",
                                    {"issue_id": "cafe123", "add": ["approved-for-dev"]})
        assert result.data["ok"] is True
        assert result.data["added"] == ["approved-for-dev"]
        assert ("issue", "label", "cafe123", "--add", "approved-for-dev") in backend.calls

    @pytest.mark.asyncio
    async def test_add_and_remove(self):
        backend = FakeRadicleBackend(
            responses={("issue", "label", "cafe123", "--add", "building", "--delete", "approved-for-dev"): "ok"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.issue_label",
                                    {"issue_id": "cafe123", "add": ["building"], "remove": ["approved-for-dev"]})
        assert result.data["ok"] is True

    @pytest.mark.asyncio
    async def test_no_labels_fails(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.issue_label", {"issue_id": "cafe123"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

_RAD_INIT = """\
Initializing radicle 👾 repository in /fake/repo..

✓ Repository widget created.

Your Repository ID (RID) is rad:z2A5ozGWKwFbTHDvC5c6nQ3AL9F2z
"""


class TestInit:
    @pytest.mark.asyncio
    async def test_returns_rid_private_by_default(self):
        # No default_branch is passed by default — forcing one that doesn't exist breaks rad init.
        args = ("init", "/fake/repo", "--name", "widget", "--description", "A widget",
                "--no-confirm", "--private")
        backend = FakeRadicleBackend(responses={args: _RAD_INIT})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.init", {"name": "widget", "description": "A widget"})
        assert result.data["rid"] == "rad:z2A5ozGWKwFbTHDvC5c6nQ3AL9F2z"
        assert result.data["visibility"] == "private"
        assert result.data["ok"] is True
        assert backend.calls[0] == args  # non-interactive (--no-confirm), explicit visibility, no forced branch

    @pytest.mark.asyncio
    async def test_public_visibility(self):
        args = ("init", "/fake/repo", "--name", "widget", "--description", "",
                "--no-confirm", "--public")
        backend = FakeRadicleBackend(responses={args: _RAD_INIT})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.init", {"name": "widget", "private": False})
        assert result.data["visibility"] == "public"
        assert result.data["rid"].startswith("rad:")

    @pytest.mark.asyncio
    async def test_default_branch_passed_only_when_specified(self):
        args = ("init", "/fake/repo", "--name", "widget", "--description", "",
                "--no-confirm", "--private", "--default-branch", "trunk")
        backend = FakeRadicleBackend(responses={args: _RAD_INIT})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.init", {"name": "widget", "default_branch": "trunk"})
        assert result.data["ok"] is True
        assert backend.calls[0] == args

    @pytest.mark.asyncio
    async def test_missing_name_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.init", {"description": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.init", {"name": "w", "unknown": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_error_propagates(self):
        class ErrorBackend(FakeRadicleBackend):
            def run(self, *args, cwd=None):
                raise RuntimeError("already initialized")
        host = _make_host(ErrorBackend())
        result = await host.ainvoke("chp.adapters.radicle.init", {"name": "w"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# patch_merge — fixtures are the REAL rad 1.9.1 push-marks-merged output
# (captured live: checkout -> git merge --ff-only -> git push rad <default>)
# ---------------------------------------------------------------------------

_RAD_PUSH_MERGED = """\
✓ Patch 2594c826a46af7d15e1e21668adbcd4848c7224b merged
✓ Canonical reference refs/heads/main updated to target commit 8342b3d5ac966322699036cefb2e8df32b69bd3c
To rad://z2PM8DYB1XKjbF3ZCZejLn5LPZTxi/z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn
   781eb73..8342b3d  main -> main
"""


class TestPatchMerge:
    @pytest.mark.asyncio
    async def test_merges_and_advances_canonical(self):
        backend = FakeRadicleBackend(push_responses={("rad", "main"): _RAD_PUSH_MERGED})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_merge", {"patch_id": "2594c82"})
        assert result.outcome == "success"
        assert result.data["merged"] is True
        assert result.data["canonical_commit"] == "8342b3d5ac966322699036cefb2e8df32b69bd3c"
        # the live-verified sequence: rad patch checkout -> git checkout -> git merge --ff-only -> push
        assert ("patch", "checkout", "2594c82", "--name", "patch-2594c82") in backend.calls
        assert ("checkout", "main") in backend.git_calls
        assert ("merge", "--ff-only", "patch-2594c82") in backend.git_calls
        assert ("rad", "main") in backend.push_calls

    @pytest.mark.asyncio
    async def test_conflict_fails_before_any_push(self):
        # A non-fast-forward merge raises; the push MUST NOT happen — canonical branch stays untouched.
        class ConflictBackend(FakeRadicleBackend):
            def git(self, *args, cwd=None):
                self.git_calls.append(args)
                if args and args[0] == "merge":
                    raise RuntimeError("fatal: Not possible to fast-forward, aborting.")
                return ""
        backend = ConflictBackend()
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_merge", {"patch_id": "2594c82"})
        assert result.outcome == "failure"
        assert backend.push_calls == []  # never pushed → no canonical mutation

    @pytest.mark.asyncio
    async def test_patch_id_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_merge", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_merge", {"patch_id": "x", "unknown": "y"})
        assert result.outcome == "denied"


# ---------------------------------------------------------------------------
# restore (Go Back)
# ---------------------------------------------------------------------------

class TestRestore:
    @pytest.mark.asyncio
    async def test_restore_appends_commit_and_pushes(self):
        backend = FakeRadicleBackend(git_responses={("rev-parse", "HEAD"): "newsha1234"})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.restore", {"revision": "rev123"})
        assert result.outcome == "success"
        assert result.data["restored_from"] == "rev123"
        assert result.data["revision"] == "newsha1234"
        assert result.data["ok"] is True
        # append-only idiom: hard-reset to revision, soft-reset back to old HEAD, commit, push canonical
        assert ("reset", "--hard", "rev123") in backend.git_calls
        assert ("reset", "--soft", "newsha1234") in backend.git_calls
        assert ("rad", "main") in backend.push_calls

    @pytest.mark.asyncio
    async def test_revision_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.restore", {})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_fails_cleanly_without_pushing(self):
        class ConflictBackend(FakeRadicleBackend):
            def git(self, *args, cwd=None):
                self.git_calls.append(args)
                if len(args) > 4 and args[4] == "commit":
                    raise RuntimeError("nothing to commit")
                if args[:2] == ("rev-parse", "HEAD"):
                    return "sha"
                return ""
        backend = ConflictBackend()
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.restore", {"revision": "rev123"})
        assert result.outcome == "failure"
        assert backend.push_calls == []  # never pushed on failure — canonical untouched


# ---------------------------------------------------------------------------
# clone (recover a RID from the network)
# ---------------------------------------------------------------------------

class TestClone:
    @pytest.mark.asyncio
    async def test_clones_rid_to_dest(self):
        args = ("clone", "rad:z2A5ozGWKwFbTHDvC5c6nQ3AL9F2z", "/tmp/recover")
        backend = FakeRadicleBackend(responses={args: "✓ Creating checkout in /tmp/recover.."})
        host = _make_host(backend)
        result = await host.ainvoke(
            "chp.adapters.radicle.clone",
            {"rid": "rad:z2A5ozGWKwFbTHDvC5c6nQ3AL9F2z", "dest": "/tmp/recover"},
        )
        assert result.outcome == "success"
        assert result.data["rid"] == "rad:z2A5ozGWKwFbTHDvC5c6nQ3AL9F2z"
        assert result.data["dest"] == "/tmp/recover"
        assert result.data["ok"] is True
        assert backend.calls[0] == args  # dest passed positionally, non-interactive

    @pytest.mark.asyncio
    async def test_seed_and_scope_flags(self):
        args = ("clone", "rad:zABC", "/tmp/r", "--seed", "z6Mk", "--scope", "followed")
        backend = FakeRadicleBackend(responses={args: ""})
        host = _make_host(backend)
        result = await host.ainvoke(
            "chp.adapters.radicle.clone",
            {"rid": "rad:zABC", "dest": "/tmp/r", "seed": "z6Mk", "scope": "followed"},
        )
        assert result.outcome == "success"
        assert backend.calls[0] == args

    @pytest.mark.asyncio
    async def test_parses_checkout_path_when_no_dest(self):
        backend = FakeRadicleBackend(responses={("clone", "rad:zABC"): "✓ Creating checkout in ./widget.."})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.clone", {"rid": "rad:zABC"})
        assert result.data["dest"] == "./widget"

    @pytest.mark.asyncio
    async def test_rid_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.clone", {"dest": "/tmp/r"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_unknown_field_denied(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.clone", {"rid": "rad:zABC", "unknown": "x"})
        assert result.outcome == "denied"

    @pytest.mark.asyncio
    async def test_error_propagates(self):
        class ErrorBackend(FakeRadicleBackend):
            def run(self, *args, cwd=None):
                raise RuntimeError("repository not found on any seed")
        host = _make_host(ErrorBackend())
        result = await host.ainvoke("chp.adapters.radicle.clone", {"rid": "rad:zMISSING"})
        assert result.outcome == "failure"


# ---------------------------------------------------------------------------
# patch_show (canonical diff for review)
# ---------------------------------------------------------------------------

_RAD_PATCH_DIFF = """\
diff --git a/src/app.ts b/src/app.ts
index abc1234..def5678 100644
--- a/src/app.ts
+++ b/src/app.ts
@@ -1,2 +1,2 @@
-const theme = "light";
+const theme = "dark";
diff --git a/README.md b/README.md
index 111..222 100644
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-old
+new
"""


class TestPatchShow:
    @pytest.mark.asyncio
    async def test_returns_diff_and_files(self):
        backend = FakeRadicleBackend(responses={("patch", "diff", "patch123"): _RAD_PATCH_DIFF})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_show", {"patch_id": "patch123"})
        assert result.outcome == "success"
        assert result.data["patch_id"] == "patch123"
        assert 'const theme = "dark"' in result.data["diff"]  # the REAL canonical change
        assert result.data["files"] == ["README.md", "src/app.ts"]  # parsed from +++ b/ lines, sorted
        assert result.data["ok"] is True
        assert backend.calls[0] == ("patch", "diff", "patch123")

    @pytest.mark.asyncio
    async def test_diff_never_in_evidence(self):
        # The diff is a RETURN value; evidence carries only patch id + file count (patch_list discipline).
        import json as _json
        backend = FakeRadicleBackend(responses={("patch", "diff", "p"): _RAD_PATCH_DIFF})
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.radicle.patch_show", {"patch_id": "p"})
        assert result.outcome == "success"
        evidence = _json.dumps(host.store.all())
        assert 'const theme = "dark"' not in evidence  # the diff text NEVER enters the evidence stream
        assert "patch_show" in evidence  # but the operation itself IS recorded

    @pytest.mark.asyncio
    async def test_patch_id_required(self):
        host = _make_host(FakeRadicleBackend())
        result = await host.ainvoke("chp.adapters.radicle.patch_show", {})
        assert result.outcome == "denied"
