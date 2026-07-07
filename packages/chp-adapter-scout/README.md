# chp-adapter-scout

Repo-exploration subagent powered by FastContext-1.0. Given a task and repo path, returns compact file:line citations so the frontier model does not need to explore the repository itself.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `query` | medium | Ask the FastContext scout to locate relevant files for a task. Returns file:line citations. The frontier model |

## Notes

Every capability is governed (risk-assessed via `safety.assess`) and evidenced (redacted: counts/ids, never payloads). Mutating ops may require approval.

_README generated deterministically from the adapter's `@capability` metadata (`stewards/gen_readme.py`); refine the prose as needed._
