# chp-adapter-github

GitHub inspection as governed [Capability Host Protocol](https://capabilityhostprotocol.com)
capabilities. Read-only first slice: repositories, pull requests, issues, CI
workflow runs, and PR reviews — each exposed as `chp.adapters.github.<op>` with a
full execution evidence chain.

Built on the canonical chp-core adapter template (`BaseAdapter` + `@capability`),
the same pattern as `chp-adapter-mcp`.

## Install

```bash
pip install chp-adapter-github
```

## Usage

```python
from chp_core import LocalCapabilityHost, register_adapter
from chp_adapter_github import GitHubAdapter, GitHubConfig

host = LocalCapabilityHost()
register_adapter(host, GitHubAdapter(GitHubConfig()))  # token from GITHUB_TOKEN

pr = host.invoke("chp.adapters.github.get_pull_request", {
    "owner": "capabilityhostprotocol", "repo": "chp-core", "number": 1,
})
print(pr.data["state"], pr.data["mergeable_state"])
```

## Capabilities (read-only)

| Capability | Purpose |
|---|---|
| `chp.adapters.github.get_repo` | Repository metadata |
| `chp.adapters.github.list_pull_requests` | List PRs (state filter) |
| `chp.adapters.github.get_pull_request` | Single PR + merge/CI detail |
| `chp.adapters.github.list_issues` | List issues (PRs excluded) |
| `chp.adapters.github.get_issue` | Single issue |
| `chp.adapters.github.list_workflow_runs` | GitHub Actions CI status |
| `chp.adapters.github.list_pr_reviews` | Reviews on a PR |

Each returns a **curated projection** — a capability, not a raw API mirror.

## Auth

`GitHubConfig.token` (or the `GITHUB_TOKEN` / `GH_TOKEN` env var). A token is
optional for public reads but raises the rate limit. The token is sent in the
`Authorization` header and never appears in evidence payloads.

## Design notes

- A fresh `httpx.AsyncClient` is created per call: the host runs handlers via
  `asyncio.run` (a new loop per `host.invoke`), and an AsyncClient is loop-bound.
- `GitHubConfig.transport` accepts an `httpx` transport (e.g.
  `httpx.MockTransport`) for tests — no network required.
- Write operations (create issue, comment, etc.) are a deliberate later slice;
  they carry a higher risk tier and policy gates.
