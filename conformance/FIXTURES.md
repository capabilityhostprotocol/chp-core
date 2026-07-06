# CHP Conformance Fixture Profile

Status: normative for the `wire` conformance suite. A host-under-test that wants
to be validated by the black-box runner (`conformance/runner.py --url`) MUST
pre-register the capabilities below and configure the host as specified. The
runner exercises them and asserts each expected outcome, denial code, and event
sequence. Event orderings reference
[spec/chp-invocation-pipeline.md](../spec/chp-invocation-pipeline.md).

This file is the language-agnostic contract: it replaces "read the Python
`build_passing_host()`" with a spec any implementation can register from.

## Host configuration

The host under test MUST be configured with:
- **Policy:** `max_risk_tier = "medium"` (so a `high`-risk capability is blocked).
  No block-patterns or blocked-ids are required.
- **Safety evaluator:** a rule-based evaluator with one guardrail that blocks
  `conformance.unsafe` — a guardrail whose `capability_id_pattern` matches
  `conformance.unsafe` and lists it in `requires_human_for` (so it always blocks,
  regardless of the computed risk score).
- **Auth:** an `X-CHP-Key` the runner is given via `--key` / `CHP_HOST_API_KEY`.

## Capabilities

All fixtures are version `1.0.0`, `sync` mode. "Events" lists the evidence event
types emitted for the exercised call, in order.

| id | Config | Exercised with | Outcome | `denial.code` | Events (in order) |
|---|---|---|---|---|---|
| `conformance.echo` | none | `{"value": "..."}` | `success` | — | `execution_started`, `execution_completed` |
| `conformance.fail` | handler always raises | `{}` | `failure` | — | `execution_started`, `execution_failed` |
| `conformance.guarded` | host invariant `requires_value` (`required_payload_fields: ["value"]`, `failure_behavior: deny`) | `{}` (missing `value`) | `denied` | `invariant_failed` | `execution_denied` |
| `conformance.approval` | `autonomy.tier = "approval_required"` | `{}` | `denied` | `approval_required` | `approval_requested`, `execution_denied` |
| `conformance.budgeted` | `autonomy.action_limit = 1` | invoked **twice** on one correlation | 1st `success`, 2nd `denied` | (2nd) `budget_exceeded` | 1st: `execution_started`, `execution_completed`; 2nd: `budget_exceeded`, `execution_denied` |
| `conformance.risky` | `risk = "high"` | `{}` | `denied` | `policy_blocked` | `execution_denied` |
| `conformance.unsafe` | (blocked by the host guardrail above) | `{}` | `denied` | `safety_blocked` | `safety_assessment_started`, `safety_assessment_completed`, `safety_guardrail_triggered`, `safety_action_blocked`, `execution_denied` |

### Behaviour notes

- `conformance.echo` returns its input `value` in `InvocationResult.data` (e.g.
  `{"echo": "<value>"}`); the exact shape isn't asserted, only `outcome:success`.
- `conformance.fail`'s handler MUST raise so the host records `execution_failed`
  (a runtime failure, not a denial).
- `conformance.guarded` is denied at the **invariant** gate (pipeline gate 6),
  *before* safety — so it emits no safety events even on a safety-configured host.
- `conformance.risky` is denied at the **policy** gate (gate 5), before invariants,
  autonomy, and safety — so it too emits no governance side-events, only
  `execution_denied`.
- `conformance.unsafe` is the only fixture that exercises the safety pipeline;
  its assessment pair is emitted because it passed gates 1–8 and reached gate 9.
- Numbers in emitted event payloads (e.g. a safety `score`) are **string-encoded**
  per `chp-stable-v1` ([chp-v0.2.md](../spec/chp-v0.2.md) §2 rule 6) — the runner
  does not assert their value, only the event types.

## Running the check

```
<start the host under test on PORT with the config above>
python conformance/runner.py --url http://localhost:PORT --key <key> --suite wire
```
A conforming host prints `[wire] 16/16`.
