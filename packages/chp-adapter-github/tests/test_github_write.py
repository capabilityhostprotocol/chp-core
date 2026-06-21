"""Tests for chp_adapter_github write capabilities (create/update/comment/PR/labels)."""

from __future__ import annotations

import json

import httpx
import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_github import GitHubAdapter, GitHubConfig
from chp_adapter_http import HttpAdapter, HttpConfig


# --------------------------------------------------------------------------
# Fake GitHub write server
# --------------------------------------------------------------------------

ISSUE_CREATED = {
    "number": 42, "title": "New bug", "state": "open",
    "user": {"login": "alice"}, "labels": [],
    "comments": 0, "html_url": "https://github.com/octo/repo/issues/42",
}
ISSUE_UPDATED = {
    "number": 42, "title": "Updated title", "state": "closed",
    "user": {"login": "alice"}, "labels": [{"name": "wontfix"}],
    "comments": 0, "html_url": "https://github.com/octo/repo/issues/42",
}
COMMENT_CREATED = {
    "id": 9001,
    "html_url": "https://github.com/octo/repo/issues/42#issuecomment-9001",
    "created_at": "2026-06-11T00:00:00Z",
    "body": "this is the comment body",
}
PR_CREATED = {
    "number": 55, "title": "Add feature", "state": "open", "draft": False,
    "user": {"login": "alice"}, "html_url": "https://github.com/octo/repo/pull/55",
    "merged": False, "mergeable": None, "mergeable_state": "unknown",
    "head": {"ref": "feature"}, "base": {"ref": "main"},
    "additions": 0, "deletions": 0, "changed_files": 0, "comments": 0,
}
LABELS_ADDED = [
    {"id": 1, "name": "bug", "color": "d73a4a"},
    {"id": 2, "name": "priority:high", "color": "e4e669"},
]


class FakeGitHubWrite:
    """Records captured requests and returns canned responses."""

    def __init__(self):
        self.requests: list[dict] = []

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            method = request.method
            path = request.url.path
            try:
                body = json.loads(request.content) if request.content else {}
            except json.JSONDecodeError:
                body = {}
            self.requests.append({"method": method, "path": path, "body": body})
            headers = {"x-ratelimit-remaining": "58"}

            if method == "POST" and path.endswith("/issues") and "/pulls" not in path:
                return httpx.Response(201, json=ISSUE_CREATED, headers=headers)
            if method == "POST" and "/issues/" in path and path.endswith("/comments"):
                return httpx.Response(201, json=COMMENT_CREATED, headers=headers)
            if method == "PATCH" and "/issues/" in path:
                return httpx.Response(200, json=ISSUE_UPDATED, headers=headers)
            if method == "POST" and path.endswith("/pulls"):
                return httpx.Response(201, json=PR_CREATED, headers=headers)
            if method == "POST" and "/issues/" in path and path.endswith("/labels"):
                return httpx.Response(200, json=LABELS_ADDED, headers=headers)
            return httpx.Response(404, json={"message": "Not Found"}, headers=headers)

        return httpx.MockTransport(handler)


def _make_host(fake: FakeGitHubWrite | None = None, token: str = "gh_test"):
    if fake is None:
        fake = FakeGitHubWrite()
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    # GitHub composes through chp.adapters.http; the fake transport lives there.
    register_adapter(host, HttpAdapter(HttpConfig(
        transport=fake.transport(), max_retries=0, backoff_base=0.0,
    )))
    register_adapter(host, GitHubAdapter(GitHubConfig(token=token)))
    return host, fake


def _events(host):
    return [e for e in host.store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. Shape
# --------------------------------------------------------------------------

class TestWriteShape:
    def test_write_caps_are_medium_risk(self):
        for cap in GitHubAdapter().capabilities():
            if cap.descriptor.id in {
                "chp.adapters.github.create_issue",
                "chp.adapters.github.create_comment",
                "chp.adapters.github.update_issue",
                "chp.adapters.github.create_pull_request",
                "chp.adapters.github.add_labels",
            }:
                assert cap.descriptor.risk == "medium", cap.descriptor.id

    def test_read_caps_still_low_risk(self):
        for cap in GitHubAdapter().capabilities():
            if cap.descriptor.id in {
                "chp.adapters.github.get_repo",
                "chp.adapters.github.get_issue",
                "chp.adapters.github.list_issues",
            }:
                assert cap.descriptor.risk == "low"


# --------------------------------------------------------------------------
# 2. create_issue
# --------------------------------------------------------------------------

class TestCreateIssue:
    def test_success(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "New bug",
        })
        assert r.outcome == "success"
        assert r.data["number"] == 42
        assert r.data["title"] == "New bug"

    def test_sends_title_and_labels(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo",
            "title": "Bug report",
            "labels": ["bug", "priority:high"],
        })
        req = fake.requests[0]
        assert req["body"]["title"] == "Bug report"
        assert req["body"]["labels"] == ["bug", "priority:high"]

    def test_sends_body_to_github(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo",
            "title": "t", "body": "The body text",
        })
        assert fake.requests[0]["body"]["body"] == "The body text"

    def test_missing_title_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo",
        })
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "t", "injected": "bad",
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 3. create_comment
# --------------------------------------------------------------------------

class TestCreateComment:
    def test_success(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "number": 42, "body": "Hello",
        })
        assert r.outcome == "success"
        assert r.data["id"] == 9001
        assert "html_url" in r.data

    def test_sends_body_to_github(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "number": 42, "body": "My comment",
        })
        assert fake.requests[0]["body"]["body"] == "My comment"

    def test_uses_correct_path(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "number": 7, "body": "hi",
        })
        assert fake.requests[0]["path"].endswith("/issues/7/comments")

    def test_missing_body_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "number": 42,
        })
        assert r.outcome == "denied"

    def test_missing_number_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "body": "hi",
        })
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo", "number": 1,
            "body": "hi", "injected": "bad",
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 4. update_issue
# --------------------------------------------------------------------------

class TestUpdateIssue:
    def test_close_issue(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 42, "state": "closed",
        })
        assert r.outcome == "success"
        assert r.data["state"] == "closed"

    def test_update_title(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 42, "title": "New title",
        })
        assert fake.requests[0]["body"]["title"] == "New title"

    def test_update_labels(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 42,
            "labels": ["wontfix"],
        })
        assert fake.requests[0]["body"]["labels"] == ["wontfix"]

    def test_body_sent_to_github_but_not_in_evidence(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 42,
            "body": "SENSITIVE_BODY_XYZ",
        })
        # Sent to GitHub
        assert fake.requests[0]["body"]["body"] == "SENSITIVE_BODY_XYZ"
        # Not in evidence
        dump = str([e["payload"] for e in _events(host)])
        assert "SENSITIVE_BODY_XYZ" not in dump

    def test_missing_number_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo",
        })
        assert r.outcome == "denied"

    def test_invalid_state_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 1, "state": "merged",
        })
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.update_issue", {
            "owner": "octo", "repo": "repo", "number": 1, "injected": "bad",
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 5. create_pull_request
# --------------------------------------------------------------------------

class TestCreatePullRequest:
    def test_success(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo",
            "title": "Add feature", "head": "feature", "base": "main",
        })
        assert r.outcome == "success"
        assert r.data["number"] == 55
        assert r.data["head_ref"] == "feature"
        assert r.data["base_ref"] == "main"

    def test_sends_correct_fields(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo",
            "title": "My PR", "head": "feat/x", "base": "main",
            "draft": True,
        })
        b = fake.requests[0]["body"]
        assert b["title"] == "My PR"
        assert b["head"] == "feat/x"
        assert b["base"] == "main"
        assert b["draft"] is True

    def test_body_sent_not_in_evidence(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo",
            "title": "PR", "head": "feat", "base": "main",
            "body": "SENSITIVE_PR_BODY_XYZ",
        })
        assert fake.requests[0]["body"]["body"] == "SENSITIVE_PR_BODY_XYZ"
        dump = str([e["payload"] for e in _events(host)])
        assert "SENSITIVE_PR_BODY_XYZ" not in dump

    def test_missing_head_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo", "title": "t", "base": "main",
        })
        assert r.outcome == "denied"

    def test_missing_base_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo", "title": "t", "head": "feat",
        })
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.create_pull_request", {
            "owner": "octo", "repo": "repo",
            "title": "t", "head": "feat", "base": "main",
            "injected": "bad",
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 6. add_labels
# --------------------------------------------------------------------------

class TestAddLabels:
    def test_success(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.add_labels", {
            "owner": "octo", "repo": "repo",
            "number": 42, "labels": ["bug", "priority:high"],
        })
        assert r.outcome == "success"
        assert set(r.data["labels"]) == {"bug", "priority:high"}
        assert r.data["number"] == 42

    def test_sends_labels_array(self):
        host, fake = _make_host()
        host.invoke("chp.adapters.github.add_labels", {
            "owner": "octo", "repo": "repo",
            "number": 42, "labels": ["enhancement"],
        })
        assert fake.requests[0]["body"]["labels"] == ["enhancement"]

    def test_empty_labels_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.add_labels", {
            "owner": "octo", "repo": "repo", "number": 42, "labels": [],
        })
        assert r.outcome == "denied"

    def test_missing_labels_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.add_labels", {
            "owner": "octo", "repo": "repo", "number": 42,
        })
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host, _ = _make_host()
        r = host.invoke("chp.adapters.github.add_labels", {
            "owner": "octo", "repo": "repo", "number": 1,
            "labels": ["bug"], "injected": "bad",
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 7. Evidence hygiene (write ops)
# --------------------------------------------------------------------------

class TestWriteEvidenceHygiene:
    def test_token_not_in_evidence(self):
        host, _ = _make_host(token="gh_supersecret")
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "t",
        })
        dump = str([e["payload"] for e in _events(host)])
        assert "gh_supersecret" not in dump

    def test_issue_body_not_in_evidence(self):
        host, _ = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo",
            "title": "t", "body": "SENSITIVE_ISSUE_BODY_XYZ",
        })
        dump = str([e["payload"] for e in _events(host)])
        assert "SENSITIVE_ISSUE_BODY_XYZ" not in dump

    def test_comment_body_not_in_evidence(self):
        host, _ = _make_host()
        host.invoke("chp.adapters.github.create_comment", {
            "owner": "octo", "repo": "repo",
            "number": 1, "body": "SENSITIVE_COMMENT_XYZ",
        })
        dump = str([e["payload"] for e in _events(host)])
        assert "SENSITIVE_COMMENT_XYZ" not in dump

    def test_title_is_in_evidence(self):
        host, _ = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "VISIBLE_TITLE_12345",
        })
        dump = str([e["payload"] for e in _events(host)])
        assert "VISIBLE_TITLE_12345" in dump

    def test_github_request_and_response_events(self):
        host, _ = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "t",
        })
        types = [e["event_type"] for e in _events(host)]
        assert "github_request" in types
        assert "github_response" in types

    def test_no_lifecycle_events(self):
        host, _ = _make_host()
        host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "t",
        })
        lifecycle = {"execution_started", "execution_completed", "execution_failed"}
        types = {e["event_type"] for e in _events(host)}
        assert not types & lifecycle

    def test_api_error_emits_github_error(self):
        def bad(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, json={"message": "Validation Failed"},
                                  headers={"x-ratelimit-remaining": "10"})

        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, HttpAdapter(HttpConfig(
            transport=httpx.MockTransport(bad), max_retries=0, backoff_base=0.0,
        )))
        register_adapter(host, GitHubAdapter(GitHubConfig(token="t")))
        r = host.invoke("chp.adapters.github.create_issue", {
            "owner": "octo", "repo": "repo", "title": "t",
        })
        assert r.outcome == "failure"
        types = [e["event_type"] for e in _events(host)]
        assert "github_error" in types
