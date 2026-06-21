"""chp-adapter-github — GitHub inspection as governed CHP capabilities.

Read-only first slice: repository metadata, pull requests, issues, CI workflow
runs, and PR reviews — each exposed as ``chp.adapters.github.<op>`` with full
execution evidence. Built on the canonical chp-core adapter template
(``BaseAdapter`` + ``@capability``).

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_github import GitHubAdapter, GitHubConfig

    host = LocalCapabilityHost()
    register_adapter(host, GitHubAdapter(GitHubConfig()))  # token from GITHUB_TOKEN
    pr = host.invoke("chp.adapters.github.get_pull_request",
                     {"owner": "capabilityhostprotocol", "repo": "chp-core", "number": 1})
"""

from __future__ import annotations

from .adapter import GitHubAdapter, GitHubConfig

__all__ = ["GitHubAdapter", "GitHubConfig"]
