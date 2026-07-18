# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **This repository is a GENERATED PUBLIC MIRROR of the private `chp-dev` repo.** Do not hand-edit
> generated content (`packages/`, `spec/`, `schemas/`, `conformance/`, `examples/`, `docs/`, `registry/`,
> `provenance/`). Make the change in chp-dev and publish it with `scripts/sync-to-public.sh --publish`,
> which opens a **PR into protected `main`** (gated by the *Python reference host* check) plus a signed
> Radicle patch; `--land <pr#>` merges the PR and mirrors rad. Two backstops enforce this: a local
> pre-commit guard rejects hand-edits to generated paths, and the **Mirror provenance** CI check
> (`.github/workflows/mirror-provenance.yml`) rejects any PR that changes them from a non-`sync/*` branch.
> Mirror-native files (this file, `.github/`, `README`, `LICENSE`) may be edited here via a normal PR.

## Commands

```bash
# Tests
cd packages/python && python -m pytest tests/ -m "not slow" -q --no-cov   # fast suite (~6s)
cd packages/python && python -m pytest tests/ -q --no-cov                 # full suite

# Install CHP hooks into Claude Code (PostToolUse + Stop)
PYTHONPATH=packages/python chp hooks install
PYTHONPATH=packages/python chp hooks install --with-precommit   # also installs git pre-commit hook
PYTHONPATH=packages/python chp hooks install --with-prepush     # also installs git pre-push RC guard
PYTHONPATH=packages/python chp hooks status

# Session evidence (MCP tools available in-loop — prefer these over CLI)
PYTHONPATH=packages/python python -m tools.chp_inspector --store .chp/claude-code-sessions.sqlite sessions
PYTHONPATH=packages/python python -m tools.chp_inspector --store .chp/claude-code-sessions.sqlite breakdown
PYTHONPATH=packages/python python -m tools.chp_inspector --store .chp/claude-code-sessions.sqlite show <session_id>

# Policy
PYTHONPATH=packages/python chp policy lint .chp/policy.json
PYTHONPATH=packages/python chp ci check --store .chp/claude-code-sessions.sqlite --policy .chp/policy.json

# CI visibility
PYTHONPATH=packages/python chp ci status            # show latest GitHub Actions runs (uses gh CLI)
PYTHONPATH=packages/python chp ci status --limit 10 # show last 10 runs

# Development governance (emit events to .chp/codex-self-observation.sqlite)
PYTHONPATH=packages/python chp work check-alignment --repo-root .    # 41 spec/schema/type checks
PYTHONPATH=packages/python chp work vc precommit --check tests --check alignment --repo-root .
PYTHONPATH=packages/python chp work conformance-matrix --repo-root .
PYTHONPATH=packages/python chp work vc diff --repo-root .

# Web dashboard
PYTHONPATH=packages/python python -m tools.chp_dashboard --store .chp/claude-code-sessions.sqlite

# Conformance runner (direct)
PYTHONPATH=packages/python python conformance/runner.py
```

## Architecture

```
chp-core/
  packages/python/chp_core/   # Published PyPI package: chp-core
    host.py                   # LocalCapabilityHost — wraps tool calls with evidence
    store.py                  # SQLiteEvidenceStore — append-only, SHA256-chained
    hooks.py                  # Claude Code PostToolUse/Stop hook handlers
    policy.py                 # PolicyConfig, BlockPattern, evaluate_policy()
    types.py                  # Python dataclasses: CapabilityDescriptor, InvocationEnvelope, etc.
    adapters/                 # claude_code.py, codex.py, gemini_cli.py — capability_id mapping
    cli/                      # chp CLI: __init__.py, _ci.py, _work.py
    work_host.py              # build_work_host() — LocalCapabilityHost for dev workflow
    work_capabilities.py      # 6 dev capabilities: check-alignment, conformance-matrix, etc.
    protocol_checks.py        # check_alignment(repo_root) — 41 checks across spec/schema/Python/TS
  packages/ts-types/          # Published npm package: @capabilityhostprotocol/types
  tools/
    chp_inspector/            # CLI inspector: sessions, show, verify, breakdown, diff, query
    chp_mcp/                  # MCP server: chp_sessions, chp_show, chp_tree, chp_query,
                              #   chp_breakdown, chp_verify, chp_work_alignment, chp_conformance
    chp_dashboard/            # Web dashboard (stdlib HTTP, port 8080)
  examples/                   # 14 runnable demos
  conformance/runner.py       # 9-check CHP v0.1 protocol conformance runner
  spec/chp-v0.1.md            # Protocol spec (source of truth for alignment checks)
  schemas/                    # JSON Schema files for all protocol objects
```

## Evidence Stores

Two separate SQLite stores, both in `.chp/`:

| Store | Written by | Queried by |
|---|---|---|
| `.chp/claude-code-sessions.sqlite` | `chp hook post-tool` / `chp hook stop` (PostToolUse/Stop hooks) | `chp_inspector`, MCP tools, dashboard |
| `.chp/codex-self-observation.sqlite` | `chp work *` commands | `chp work summary`, `chp work replay` |

Session store = every tool call the agent makes.  
Work store = development decisions, conformance runs, precommit checks, release bundles.

## Development Invariants

These should be checked at the moments shown:

| Moment | Command | What it checks |
|---|---|---|
| Session start | `mcp__chp__chp_work_alignment` | 41 spec/schema/type sync checks |
| Session start | `mcp__chp__chp_conformance` | 9 protocol conformance checks |
| Edit `types.py`, `spec/`, or `schemas/` | `chp work check-alignment --repo-root .` | Spec drift |
| Before commit | `chp work vc precommit --check tests --check alignment --repo-root .` | Tests + alignment |
| Before release | `chp work vc release-bundle --repo-root .` | Full release evidence bundle |

## Policy

`.chp/policy.json` is auto-loaded by `chp ci check` and `chp policy lint`. It governs development:
- Blocks `rm -rf` outside `/tmp`
- Blocks `git push --force`
- Blocks raw `git tag && git push --tags` (use `chp work vc release-bundle`)

Run `chp policy lint .chp/policy.json` to validate it.

## Release Sequence (merge → version bump → RC → publish)

After a patch merges to main, the governed release sequence:

```
# 1. Bump versions (writes pyproject.toml + package.json atomically)
mcp__chp__chp_version_bump          # --new_version 0.3.0

# 2. Bundle release evidence (include correlation IDs from this dev session)
mcp__chp__chp_vc_release_bundle     # --work_correlation_ids [...]

# 3. Push RC tag → triggers CI + TestPyPI staging
mcp__chp__chp_rc_tag                # --version 0.3.0 --allow_mutation true
# CI runs extended tests + publishes to TestPyPI
# Smoke test: pip install --index-url https://test.pypi.org/simple/ chp-core==0.3.0rc1

# 4. Push release tag → triggers PyPI + npm production publish
mcp__chp__chp_release_tag           # --version 0.3.0 --release_bundle_correlation_id <id> --allow_mutation true
```

Raw `git tag v*` and `git push --tags` are blocked by `.chp/policy.json`.

## Radicle-Governed Pipeline (issue → dev → merge)

Every step emits evidence to `.chp/codex-self-observation.sqlite`.

```
0. Open issue to track the work
   mcp__chp__chp_radicle_issue_open       # requires allow_mutation=true

1. Review state
   mcp__chp__chp_vc_diff                  # what changed?
   mcp__chp__chp_radicle_status           # is Radicle in sync?
   mcp__chp__chp_radicle_patches          # open patches?
   mcp__chp__chp_radicle_issues           # open issues?

2. Pre-commit gate
   mcp__chp__chp_work_alignment           # 41 spec/type checks pass?
   mcp__chp__chp_conformance              # 9 protocol checks pass?

3. Release bundle (before pushing a patch)
   mcp__chp__chp_vc_release_bundle        # bundles diff + work traces

4. Merge gate
   mcp__chp__chp_radicle_patch_merge_dry_run   # no conflicts?
   mcp__chp__chp_vc_merge_readiness            # ready: true?

5. Merge (governed)
   mcp__chp__chp_radicle_patch_merge      # requires allow_mutation=true

6. Close issue
   mcp__chp__chp_radicle_issue_comment    # post summary, requires allow_mutation=true
   # or: PYTHONPATH=packages/python chp work radicle issue-state --issue-id <ID> --state closed --allow-mutation

7. Audit
   mcp__chp__chp_work_status              # what work events were recorded?
```

Raw Radicle mutations (`rad patch merge`, `rad push`, `rad issue open/comment`) are blocked by `.chp/policy.json` — use the MCP tools or `chp work radicle *` instead.

## MCP Session Tools (use in-loop)

The `chp` MCP server exposes these tools — prefer them over CLI during agent sessions:

```
# Session evidence (reads .chp/claude-code-sessions.sqlite)
chp_sessions                   # list recent sessions
chp_show                       # detailed session summary (files, commands, chain)
chp_breakdown                  # capability usage counts
chp_verify                     # SHA256 chain integrity
chp_query                      # filtered event query
chp_tree                       # multi-agent session tree

# Alignment / conformance
chp_work_alignment             # run 41 spec alignment checks inline
chp_conformance                # run 9 conformance checks inline

# Work store (reads/writes .chp/codex-self-observation.sqlite)
chp_work_status                # recent work events (dev decisions, Radicle ops)

# VC pipeline
chp_vc_diff                    # current working-tree diff
chp_vc_release_bundle          # generate release evidence bundle
chp_vc_merge_readiness         # final merge gate (returns ready: true/false)

# Radicle patches
chp_radicle_status             # repo sync state
chp_radicle_patches            # list patches
chp_radicle_patch_inspect      # inspect a patch
chp_radicle_patch_merge_dry_run  # test merge without executing
chp_radicle_patch_merge        # governed merge (requires allow_mutation=true)

# Radicle issues
chp_radicle_issues             # list issues
chp_radicle_issue_inspect      # inspect an issue
chp_radicle_issue_open         # create issue (requires allow_mutation=true)
chp_radicle_issue_comment      # comment/close (requires allow_mutation=true)
```
