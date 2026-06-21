# chp-adapter-git

CHP capability adapter for local Git repository inspection and operations.

## Capabilities

| Capability ID | Risk | Description |
|---|---|---|
| `chp.adapters.git.status` | low | Working tree status: branch, staged/unstaged/untracked counts |
| `chp.adapters.git.inspect_repo` | low | Repository overview: branch, HEAD SHA, remotes, commit count |
| `chp.adapters.git.log` | low | Recent commits list (sha7, author, subject, date) |
| `chp.adapters.git.diff_summary` | low | Diff statistics: files changed, insertions, deletions |
| `chp.adapters.git.precommit_check` | low | Staged file list + unstaged/untracked counts |
| `chp.adapters.git.checkout_branch` | medium | Create or switch to a branch |
| `chp.adapters.git.commit` | medium | Stage files and commit with a message |

## Evidence Hygiene

- Diff content (patch text): **never** in evidence
- File content: **never** in evidence
- Commit messages: **not** in evidence (only sha7/count in events)
- Commit subjects truncated to 80 chars in `log` output

## Usage

```python
from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
from chp_adapter_git import GitAdapter, GitConfig

store = SQLiteEvidenceStore("evidence.db")
host = LocalCapabilityHost(store=store)
host.register_adapter(GitAdapter(config=GitConfig(default_repo_path="/path/to/repo")))

result = await host.ainvoke("chp.adapters.git.status", {})
print(result.output)  # {"branch": "main", "staged": 0, "unstaged": 1, "untracked": 2, "clean": False}
```

## Testing with Injectable Backend

```python
class FakeGitBackend:
    def run(self, *args, cwd=None):
        return {"rev-parse --abbrev-ref HEAD": "main"}.get(" ".join(args), "")

adapter = GitAdapter(config=GitConfig(backend=FakeGitBackend()))
```
