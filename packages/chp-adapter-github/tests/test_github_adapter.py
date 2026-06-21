"""Tests for chp_adapter_github.adapter — mocked via httpx.MockTransport (no network)."""

from __future__ import annotations

import httpx
import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_github import GitHubAdapter, GitHubConfig
from chp_adapter_http import HttpAdapter, HttpConfig


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------

REPO_JSON = {
    "full_name": "octo/repo", "description": "demo", "default_branch": "main",
    "private": False, "open_issues_count": 3, "stargazers_count": 10,
    "html_url": "https://github.com/octo/repo",
}
PR_JSON = {
    "number": 7, "title": "Add feature", "state": "open", "draft": False,
    "user": {"login": "alice"}, "html_url": "https://github.com/octo/repo/pull/7",
    "merged": False, "mergeable": True, "mergeable_state": "clean",
    "head": {"ref": "feature"}, "base": {"ref": "main"},
    "additions": 10, "deletions": 2, "changed_files": 1, "comments": 0,
}
ISSUE_JSON = {
    "number": 4, "title": "Bug", "state": "open", "user": {"login": "bob"},
    "labels": [{"name": "bug"}], "comments": 2,
    "html_url": "https://github.com/octo/repo/issues/4",
}


def _routes(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    headers = {"x-ratelimit-remaining": "59"}
    if path == "/repos/octo/repo":
        return httpx.Response(200, json=REPO_JSON, headers=headers)
    if path == "/repos/octo/repo/pulls/7":
        return httpx.Response(200, json=PR_JSON, headers=headers)
    if path == "/repos/octo/repo/pulls":
        return httpx.Response(200, json=[PR_JSON], headers=headers)
    if path == "/repos/octo/repo/pulls/7/reviews":
        return httpx.Response(200, json=[
            {"user": {"login": "carol"}, "state": "APPROVED", "submitted_at": "2026-06-10T00:00:00Z"},
        ], headers=headers)
    if path == "/repos/octo/repo/issues":
        # Mix an issue and a PR-as-issue; the PR must be filtered out.
        return httpx.Response(200, json=[
            ISSUE_JSON,
            {"number": 7, "title": "Add feature", "state": "open",
             "pull_request": {"url": "..."}, "user": {"login": "alice"}},
        ], headers=headers)
    if path == "/repos/octo/repo/issues/4":
        return httpx.Response(200, json=ISSUE_JSON, headers=headers)
    if path == "/repos/octo/repo/actions/runs":
        return httpx.Response(200, json={"total_count": 1, "workflow_runs": [
            {"id": 99, "name": "CI", "status": "completed", "conclusion": "success",
             "head_branch": "main", "event": "push", "html_url": "https://x"},
        ]}, headers=headers)
    return httpx.Response(404, json={"message": "Not Found"}, headers=headers)


def _adapter(token=None):
    # For no-host shaping tests (capabilities()/adapter_id); HTTP not exercised.
    return GitHubAdapter(GitHubConfig(token=token))


def _make_host(token=None, routes=_routes):
    # GitHub composes through chp.adapters.http; the mock transport lives on a
    # registered HttpAdapter (max_retries=0 keeps transport-error tests fast).
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HttpAdapter(HttpConfig(
        transport=httpx.MockTransport(routes), max_retries=0, backoff_base=0.0,
    )))
    register_adapter(host, GitHubAdapter(GitHubConfig(token=token)))
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. Capability shaping
# --------------------------------------------------------------------------

class TestCapabilityShaping:
    def test_capability_ids(self):
        ids = {c.descriptor.id for c in _adapter().capabilities()}
        assert ids == {
            "chp.adapters.github.get_repo",
            "chp.adapters.github.list_pull_requests",
            "chp.adapters.github.get_pull_request",
            "chp.adapters.github.list_issues",
            "chp.adapters.github.get_issue",
            "chp.adapters.github.list_workflow_runs",
            "chp.adapters.github.list_pr_reviews",
            "chp.adapters.github.create_issue",
            "chp.adapters.github.create_comment",
            "chp.adapters.github.update_issue",
            "chp.adapters.github.create_pull_request",
            "chp.adapters.github.add_labels",
        }

    def test_descriptor_metadata(self):
        cap = next(c for c in _adapter().capabilities()
                   if c.descriptor.id.endswith("get_repo"))
        assert cap.descriptor.provider == "github"
        assert cap.descriptor.risk == "low"
        assert cap.descriptor.category == "integration"

    def test_adapter_id(self):
        assert _adapter().adapter_id == "chp.adapters.github"


# --------------------------------------------------------------------------
# 2. Success projections
# --------------------------------------------------------------------------

class TestProjections:
    def test_get_repo(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        assert r.outcome == "success"
        assert r.data["full_name"] == "octo/repo"
        assert r.data["default_branch"] == "main"

    def test_get_pull_request_detail(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.get_pull_request",
                        {"owner": "octo", "repo": "repo", "number": 7})
        assert r.data["mergeable_state"] == "clean"
        assert r.data["head_ref"] == "feature"
        assert r.data["base_ref"] == "main"
        assert r.data["user"] == "alice"

    def test_list_pull_requests(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.list_pull_requests", {"owner": "octo", "repo": "repo"})
        assert [p["number"] for p in r.data["pull_requests"]] == [7]

    def test_list_issues_excludes_prs(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.list_issues", {"owner": "octo", "repo": "repo"})
        numbers = [i["number"] for i in r.data["issues"]]
        assert numbers == [4]  # the PR-as-issue (#7) filtered out
        assert r.data["issues"][0]["labels"] == ["bug"]

    def test_list_workflow_runs(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.list_workflow_runs", {"owner": "octo", "repo": "repo"})
        assert r.data["total_count"] == 1
        assert r.data["runs"][0]["conclusion"] == "success"

    def test_list_pr_reviews(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.list_pr_reviews",
                        {"owner": "octo", "repo": "repo", "number": 7})
        assert r.data["reviews"][0]["state"] == "APPROVED"


# --------------------------------------------------------------------------
# 3. Evidence
# --------------------------------------------------------------------------

class TestEvidence:
    def test_event_sequence(self):
        host = _make_host()
        host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        types = [e["event_type"] for e in _cap_events(host.store)]
        # GitHub-domain events bracket the call; the composed http transport
        # contributes its own nested http_request/http_response in between.
        assert types[0] == "github_request"
        assert types[-1] == "github_response"
        assert "http_request" in types and "http_response" in types

    def test_response_records_rate_remaining(self):
        host = _make_host()
        host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        resp = next(e for e in _cap_events(host.store) if e["event_type"] == "github_response")
        assert resp["payload"]["rate_remaining"] == "59"


# --------------------------------------------------------------------------
# 4. Failure path
# --------------------------------------------------------------------------

class TestFailure:
    def test_404_emits_execution_failed(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "missing"})
        assert r.outcome == "failure"
        failed = next(e for e in _cap_events(host.store) if e["event_type"] == "github_error")
        assert failed["payload"]["status"] == 404
        assert failed["payload"]["error"] == "Not Found"

    def test_transport_error_emits_execution_failed(self):
        def boom(request):
            raise httpx.ConnectError("no route to host")
        host = _make_host(routes=boom)
        r = host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        assert r.outcome == "failure"
        failed = next(e for e in _cap_events(host.store) if e["event_type"] == "github_error")
        # Transport failure now surfaces via the composed http adapter.
        assert failed["payload"]["reason"] == "http_unavailable"


# --------------------------------------------------------------------------
# 5. Token hygiene
# --------------------------------------------------------------------------

class TestTokenHygiene:
    def test_token_sent_as_bearer(self):
        seen = {}

        def capture(request):
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=REPO_JSON, headers={"x-ratelimit-remaining": "10"})

        host = _make_host(token="secret123", routes=capture)
        host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        assert seen["auth"] == "Bearer secret123"

    def test_token_never_in_evidence(self):
        host = _make_host(token="secret123")
        host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "secret123" not in dump


# --------------------------------------------------------------------------
# 6. input_schema guard
# --------------------------------------------------------------------------

class TestInputSchemaGuard:
    def test_missing_repo_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.get_repo", {"owner": "octo"})
        assert r.outcome == "denied"

    def test_unknown_field_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.get_repo",
                        {"owner": "octo", "repo": "repo", "bogus": 1})
        assert r.outcome == "denied"

    def test_bad_state_enum_denied(self):
        host = _make_host()
        r = host.invoke("chp.adapters.github.list_issues",
                        {"owner": "octo", "repo": "repo", "state": "weird"})
        assert r.outcome == "denied"
