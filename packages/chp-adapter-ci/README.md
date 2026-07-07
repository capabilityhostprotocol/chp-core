# chp-adapter-ci

Run pytest across CHP packages as governed capability calls. Each suite is a separate evidence-producing invocation.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `run_suite` | low | Run pytest for a single package and emit pass/fail evidence. Output is not recorded — only counts and duration |
| `run_all` | low | Run pytest across all packages in the repo. Each suite is a separate ctx.ainvoke(run_suite) call — every packa |

## Notes

Every capability is governed (risk-assessed via `safety.assess`) and evidenced (redacted: counts/ids, never payloads). Mutating ops may require approval.

_README generated deterministically from the adapter's `@capability` metadata (`stewards/gen_readme.py`); refine the prose as needed._
