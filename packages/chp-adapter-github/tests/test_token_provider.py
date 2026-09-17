"""GitHubConfig.token_provider — inject a per-invocation (scoped/short-lived) bearer
token without subclassing the adapter. (rad:d7d22ca)"""

from __future__ import annotations

import httpx
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_github import GitHubAdapter, GitHubConfig
from chp_adapter_http import HttpAdapter, HttpConfig

REPO_JSON = {"full_name": "octo/repo", "default_branch": "main", "private": False,
             "stargazers_count": 1, "open_issues_count": 0}


def _host(config: GitHubConfig):
    seen: dict = {}

    def capture(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=REPO_JSON, headers={"x-ratelimit-remaining": "9"})

    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HttpAdapter(HttpConfig(
        transport=httpx.MockTransport(capture), max_retries=0, backoff_base=0.0)))
    register_adapter(host, GitHubAdapter(config))
    return host, seen


def _get_repo(host):
    return host.invoke("chp.adapters.github.get_repo", {"owner": "octo", "repo": "repo"})


def test_sync_ctx_provider():
    host, seen = _host(GitHubConfig(token_provider=lambda ctx: "scoped-sync"))
    _get_repo(host)
    assert seen["auth"] == "Bearer scoped-sync"


def test_async_provider():
    async def provider(ctx):
        return "scoped-async"
    host, seen = _host(GitHubConfig(token_provider=provider))
    _get_repo(host)
    assert seen["auth"] == "Bearer scoped-async"


def test_zero_arg_provider():
    host, seen = _host(GitHubConfig(token_provider=lambda: "scoped-noarg"))
    _get_repo(host)
    assert seen["auth"] == "Bearer scoped-noarg"


def test_provider_overrides_static_token():
    host, seen = _host(GitHubConfig(token="static", token_provider=lambda ctx: "dynamic"))
    _get_repo(host)
    assert seen["auth"] == "Bearer dynamic"


def test_no_provider_is_backward_compatible():
    host, seen = _host(GitHubConfig(token="static-only"))
    _get_repo(host)
    assert seen["auth"] == "Bearer static-only"


def test_provider_returning_none_is_unauthenticated():
    host, seen = _host(GitHubConfig(token="ignored", token_provider=lambda ctx: None))
    _get_repo(host)
    assert seen["auth"] is None  # provider present but yields no token → no Authorization header
