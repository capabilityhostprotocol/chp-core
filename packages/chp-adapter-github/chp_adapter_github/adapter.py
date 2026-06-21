"""GitHubAdapter — GitHub repository inspection and write operations as CHP capabilities.

Each capability proxies one GitHub REST endpoint, emits a full evidence chain,
and returns a curated projection (a capability, not a raw API mirror). A fresh
``httpx.AsyncClient`` is created per call because the host runs handlers via
``asyncio.run`` (a new event loop per ``host.invoke``) and an AsyncClient binds
its connection pool to the loop it was created on — per-call clients keep the
adapter loop-safe with no shared state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_HTTP_CAP = "chp.adapters.http.request"

MAX_ERROR_LEN = 500
_API_VERSION = "2022-11-28"
_DEFAULT_BASE_URL = "https://api.github.com"
_DEFAULT_TIMEOUT = 30.0

# Domain events only — the host owns execution_started/completed/failed.
_EMITS = [
    "github_request",
    "github_response",
    "github_error",
]

# Reusable JSON Schema fragments
_OWNER_REPO = {
    "owner": {"type": "string", "minLength": 1},
    "repo": {"type": "string", "minLength": 1},
}
_STATE = {"type": "string", "enum": ["open", "closed", "all"]}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": 100}


@dataclass(slots=True)
class GitHubConfig:
    """Connection config for the GitHub adapter.

    ``token`` defaults to the ``GITHUB_TOKEN`` / ``GH_TOKEN`` env var. A token is
    optional (public reads work unauthenticated, at a lower rate limit).

    HTTP is performed by composing through ``chp.adapters.http`` (the sole
    sanctioned transport) — this adapter imports no HTTP client. Tests inject an
    ``httpx.MockTransport`` on a registered ``HttpAdapter``, not here.
    """

    token: str | None = None
    base_url: str = _DEFAULT_BASE_URL
    timeout: float = _DEFAULT_TIMEOUT

    def resolved_token(self) -> str | None:
        return self.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


class GitHubAdapter(BaseAdapter):
    """GitHub repository / PR / issue / CI inspection as CHP capabilities."""

    adapter_id = "chp.adapters.github"
    adapter_name = "GitHub"
    adapter_description = "GitHub inspection and write operations (repos, PRs, issues, CI, reviews)."
    adapter_category = "integration"
    adapter_tags = ["github", "vcs", "ci"]

    def __init__(self, config: GitHubConfig | None = None) -> None:
        self._config = config or GitHubConfig()

    # -- HTTP + evidence core ----------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        }
        token = self._config.resolved_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _http(
        self,
        ctx: Any,
        *,
        op: str,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict | None = None,
        started: dict[str, Any] | None = None,
    ) -> Any:
        """Perform a GitHub API call by composing through chp.adapters.http.

        This adapter imports no HTTP client; the request (with retries +
        circuit-breaking) is governed by the http transport adapter, which
        produces its own evidence chain. We emit GitHub-domain events here.
        """
        ctx.emit("github_request", {"op": op, "method": method, "path": path, **(started or {})}, redacted=False)

        req: dict[str, Any] = {
            "method": method,
            "url": self._config.base_url.rstrip("/") + path,
            "headers": self._headers(),
            "timeout": self._config.timeout,
        }
        if params:
            req["params"] = {k: str(v) for k, v in params.items()}
        if json_body is not None:
            req["json_body"] = json_body

        result = await ctx.ainvoke(_HTTP_CAP, req)
        if not getattr(result, "success", False):
            ctx.emit("github_error", {
                "op": op,
                "reason": "http_unavailable",
                "error": str(getattr(result, "error", "http adapter unavailable"))[:MAX_ERROR_LEN],
            }, redacted=False)
            raise RuntimeError(f"GitHub {op} failed: http adapter unavailable (is chp.adapters.http registered?)")

        data = result.data
        status = data.get("status_code")
        rate_remaining = (data.get("headers") or {}).get("x-ratelimit-remaining")
        if status is None or status >= 400:
            body_json = data.get("json")
            msg = body_json.get("message") if isinstance(body_json, dict) else None
            ctx.emit("github_error", {
                "op": op,
                "status": status,
                "error": str(msg or data.get("body") or f"HTTP {status}")[:MAX_ERROR_LEN],
                "rate_remaining": rate_remaining,
            }, redacted=False)
            raise RuntimeError(f"GitHub {op} failed: HTTP {status}")

        ctx.emit("github_response", {
            "op": op,
            "status": status,
            "rate_remaining": rate_remaining,
        }, redacted=False)
        return data.get("json")

    async def _request(
        self,
        ctx: Any,
        *,
        op: str,
        path: str,
        params: dict[str, Any] | None = None,
        started: dict[str, Any] | None = None,
    ) -> Any:
        return await self._http(ctx, op=op, method="GET", path=path, params=params, started=started)

    # -- capabilities -------------------------------------------------------

    @capability(
        id="chp.adapters.github.get_repo",
        version="1.0.0",
        description="Get repository metadata.",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": dict(_OWNER_REPO),
            "required": ["owner", "repo"],
            "additionalProperties": False,
        },
    )
    async def get_repo(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        data = await self._request(
            ctx, op="get_repo", path=f"/repos/{owner}/{repo}",
            started={"owner": owner, "repo": repo},
        )
        return _project_repo(data)

    @capability(
        id="chp.adapters.github.list_pull_requests",
        version="1.0.0",
        description="List pull requests for a repository.",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "state": _STATE, "limit": _LIMIT},
            "required": ["owner", "repo"],
            "additionalProperties": False,
        },
    )
    async def list_pull_requests(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        state = payload.get("state", "open")
        limit = int(payload.get("limit", 30))
        data = await self._request(
            ctx, op="list_pull_requests", path=f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "per_page": limit},
            started={"owner": owner, "repo": repo, "state": state},
        )
        return {"pull_requests": [_project_pr_summary(p) for p in data]}

    @capability(
        id="chp.adapters.github.get_pull_request",
        version="1.0.0",
        description="Get a single pull request with merge/CI detail.",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "number": {"type": "integer", "minimum": 1}},
            "required": ["owner", "repo", "number"],
            "additionalProperties": False,
        },
    )
    async def get_pull_request(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        data = await self._request(
            ctx, op="get_pull_request", path=f"/repos/{owner}/{repo}/pulls/{number}",
            started={"owner": owner, "repo": repo, "number": number},
        )
        return _project_pr(data)

    @capability(
        id="chp.adapters.github.list_issues",
        version="1.0.0",
        description="List issues for a repository (pull requests excluded).",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "state": _STATE, "limit": _LIMIT},
            "required": ["owner", "repo"],
            "additionalProperties": False,
        },
    )
    async def list_issues(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        state = payload.get("state", "open")
        limit = int(payload.get("limit", 30))
        data = await self._request(
            ctx, op="list_issues", path=f"/repos/{owner}/{repo}/issues",
            params={"state": state, "per_page": limit},
            started={"owner": owner, "repo": repo, "state": state},
        )
        # The issues endpoint also returns PRs; filter them out.
        issues = [_project_issue(i) for i in data if "pull_request" not in i]
        return {"issues": issues}

    @capability(
        id="chp.adapters.github.get_issue",
        version="1.0.0",
        description="Get a single issue.",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "number": {"type": "integer", "minimum": 1}},
            "required": ["owner", "repo", "number"],
            "additionalProperties": False,
        },
    )
    async def get_issue(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        data = await self._request(
            ctx, op="get_issue", path=f"/repos/{owner}/{repo}/issues/{number}",
            started={"owner": owner, "repo": repo, "number": number},
        )
        return _project_issue(data)

    @capability(
        id="chp.adapters.github.list_workflow_runs",
        version="1.0.0",
        description="List recent GitHub Actions workflow runs (CI status).",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "branch": {"type": "string"}, "limit": _LIMIT},
            "required": ["owner", "repo"],
            "additionalProperties": False,
        },
    )
    async def list_workflow_runs(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        limit = int(payload.get("limit", 20))
        params: dict[str, Any] = {"per_page": limit}
        if payload.get("branch"):
            params["branch"] = payload["branch"]
        data = await self._request(
            ctx, op="list_workflow_runs", path=f"/repos/{owner}/{repo}/actions/runs",
            params=params, started={"owner": owner, "repo": repo},
        )
        runs = [_project_run(r) for r in data.get("workflow_runs", [])]
        return {"total_count": data.get("total_count", len(runs)), "runs": runs}

    @capability(
        id="chp.adapters.github.list_pr_reviews",
        version="1.0.0",
        description="List reviews on a pull request.",
        category="integration", provider="github", risk="low", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {**_OWNER_REPO, "number": {"type": "integer", "minimum": 1}},
            "required": ["owner", "repo", "number"],
            "additionalProperties": False,
        },
    )
    async def list_pr_reviews(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        data = await self._request(
            ctx, op="list_pr_reviews", path=f"/repos/{owner}/{repo}/pulls/{number}/reviews",
            started={"owner": owner, "repo": repo, "number": number},
        )
        return {"reviews": [_project_review(r) for r in data]}


    # -- write helper -------------------------------------------------------

    async def _mutate(
        self,
        ctx: Any,
        *,
        op: str,
        method: str,
        path: str,
        json_body: dict,
        started: dict[str, Any] | None = None,
    ) -> Any:
        return await self._http(ctx, op=op, method=method, path=path, json_body=json_body, started=started)

    # -- write capabilities -------------------------------------------------

    @capability(
        id="chp.adapters.github.create_issue",
        version="1.0.0",
        description="Create a new issue in a repository.",
        category="integration", provider="github", risk="medium", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                **_OWNER_REPO,
                "title": {"type": "string", "minLength": 1},
                "body": {"type": "string", "description": "Issue body (not stored in evidence)."},
                "labels": {"type": "array", "items": {"type": "string"}},
                "assignees": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["owner", "repo", "title"],
            "additionalProperties": False,
        },
    )
    async def create_issue(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        title = payload["title"]
        body: dict[str, Any] = {"title": title}
        if payload.get("body"):
            body["body"] = payload["body"]          # sent to GitHub, not in evidence
        if payload.get("labels"):
            body["labels"] = payload["labels"]
        if payload.get("assignees"):
            body["assignees"] = payload["assignees"]

        data = await self._mutate(
            ctx, op="create_issue", method="POST",
            path=f"/repos/{owner}/{repo}/issues",
            json_body=body,
            started={"owner": owner, "repo": repo, "title": title,
                     "labels": payload.get("labels", [])},
        )
        return _project_issue(data)

    @capability(
        id="chp.adapters.github.create_comment",
        version="1.0.0",
        description="Add a comment to an issue or pull request.",
        category="integration", provider="github", risk="medium", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                **_OWNER_REPO,
                "number": {"type": "integer", "minimum": 1},
                "body": {"type": "string", "minLength": 1,
                         "description": "Comment text (not stored in evidence)."},
            },
            "required": ["owner", "repo", "number", "body"],
            "additionalProperties": False,
        },
    )
    async def create_comment(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        # body sent to GitHub but intentionally absent from evidence
        data = await self._mutate(
            ctx, op="create_comment", method="POST",
            path=f"/repos/{owner}/{repo}/issues/{number}/comments",
            json_body={"body": payload["body"]},
            started={"owner": owner, "repo": repo, "number": number},
        )
        return {"id": data.get("id"), "html_url": data.get("html_url"),
                "created_at": data.get("created_at")}

    @capability(
        id="chp.adapters.github.update_issue",
        version="1.0.0",
        description="Update an issue (title, state, labels, assignees).",
        category="integration", provider="github", risk="medium", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                **_OWNER_REPO,
                "number": {"type": "integer", "minimum": 1},
                "title": {"type": "string"},
                "state": {"type": "string", "enum": ["open", "closed"]},
                "body": {"type": "string", "description": "Updated body (not stored in evidence)."},
                "labels": {"type": "array", "items": {"type": "string"}},
                "assignees": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["owner", "repo", "number"],
            "additionalProperties": False,
        },
    )
    async def update_issue(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        update: dict[str, Any] = {}
        if payload.get("title") is not None:
            update["title"] = payload["title"]
        if payload.get("state") is not None:
            update["state"] = payload["state"]
        if payload.get("body") is not None:
            update["body"] = payload["body"]        # not in evidence
        if payload.get("labels") is not None:
            update["labels"] = payload["labels"]
        if payload.get("assignees") is not None:
            update["assignees"] = payload["assignees"]

        data = await self._mutate(
            ctx, op="update_issue", method="PATCH",
            path=f"/repos/{owner}/{repo}/issues/{number}",
            json_body=update,
            started={"owner": owner, "repo": repo, "number": number,
                     "fields": [k for k in update if k != "body"]},
        )
        return _project_issue(data)

    @capability(
        id="chp.adapters.github.create_pull_request",
        version="1.0.0",
        description="Open a new pull request.",
        category="integration", provider="github", risk="medium", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                **_OWNER_REPO,
                "title": {"type": "string", "minLength": 1},
                "head": {"type": "string", "description": "Source branch (or user:branch)."},
                "base": {"type": "string", "description": "Target branch."},
                "body": {"type": "string", "description": "PR description (not stored in evidence)."},
                "draft": {"type": "boolean"},
            },
            "required": ["owner", "repo", "title", "head", "base"],
            "additionalProperties": False,
        },
    )
    async def create_pull_request(self, ctx, payload):
        owner, repo = payload["owner"], payload["repo"]
        title, head, base = payload["title"], payload["head"], payload["base"]
        pr_body: dict[str, Any] = {"title": title, "head": head, "base": base}
        if payload.get("body"):
            pr_body["body"] = payload["body"]       # not in evidence
        if payload.get("draft") is not None:
            pr_body["draft"] = payload["draft"]

        data = await self._mutate(
            ctx, op="create_pull_request", method="POST",
            path=f"/repos/{owner}/{repo}/pulls",
            json_body=pr_body,
            started={"owner": owner, "repo": repo, "title": title,
                     "head": head, "base": base},
        )
        projected = _project_pr(data)
        # Emit PR identity so number + URL are queryable without inspecting invocation blobs
        ctx.emit("github_response", {
            "op": "pr_created",
            "pr_number": projected["number"],
            "pr_url": projected["html_url"],
            "owner": owner,
            "repo": repo,
        })
        return projected

    @capability(
        id="chp.adapters.github.add_labels",
        version="1.0.0",
        description="Add labels to an issue or pull request.",
        category="integration", provider="github", risk="medium", emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                **_OWNER_REPO,
                "number": {"type": "integer", "minimum": 1},
                "labels": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            },
            "required": ["owner", "repo", "number", "labels"],
            "additionalProperties": False,
        },
    )
    async def add_labels(self, ctx, payload):
        owner, repo, number = payload["owner"], payload["repo"], payload["number"]
        labels = payload["labels"]
        data = await self._mutate(
            ctx, op="add_labels", method="POST",
            path=f"/repos/{owner}/{repo}/issues/{number}/labels",
            json_body={"labels": labels},
            started={"owner": owner, "repo": repo, "number": number, "labels": labels},
        )
        applied = [l["name"] for l in data if isinstance(l, dict) and "name" in l]
        return {"number": number, "labels": applied}


# --------------------------------------------------------------------------
# Projections — curated subsets (capabilities, not raw API mirrors)
# --------------------------------------------------------------------------

def _login(user: Any) -> str | None:
    return user.get("login") if isinstance(user, dict) else None


def _project_repo(d: dict) -> dict:
    return {
        "full_name": d.get("full_name"),
        "description": d.get("description"),
        "default_branch": d.get("default_branch"),
        "private": d.get("private"),
        "open_issues_count": d.get("open_issues_count"),
        "stargazers_count": d.get("stargazers_count"),
        "html_url": d.get("html_url"),
    }


def _project_pr_summary(d: dict) -> dict:
    return {
        "number": d.get("number"),
        "title": d.get("title"),
        "state": d.get("state"),
        "draft": d.get("draft"),
        "user": _login(d.get("user")),
        "html_url": d.get("html_url"),
    }


def _project_pr(d: dict) -> dict:
    return {
        **_project_pr_summary(d),
        "merged": d.get("merged"),
        "mergeable": d.get("mergeable"),
        "mergeable_state": d.get("mergeable_state"),
        "head_ref": (d.get("head") or {}).get("ref"),
        "base_ref": (d.get("base") or {}).get("ref"),
        "additions": d.get("additions"),
        "deletions": d.get("deletions"),
        "changed_files": d.get("changed_files"),
        "comments": d.get("comments"),
    }


def _project_issue(d: dict) -> dict:
    return {
        "number": d.get("number"),
        "title": d.get("title"),
        "state": d.get("state"),
        "user": _login(d.get("user")),
        "labels": [l.get("name") for l in d.get("labels", []) if isinstance(l, dict)],
        "comments": d.get("comments"),
        "html_url": d.get("html_url"),
    }


def _project_run(d: dict) -> dict:
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "status": d.get("status"),
        "conclusion": d.get("conclusion"),
        "head_branch": d.get("head_branch"),
        "event": d.get("event"),
        "html_url": d.get("html_url"),
    }


def _project_review(d: dict) -> dict:
    return {
        "user": _login(d.get("user")),
        "state": d.get("state"),
        "submitted_at": d.get("submitted_at"),
    }


