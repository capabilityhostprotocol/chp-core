# Capability Host Protocol — Governed Invocation Pipeline (v0.2)

Status: **released** (v0.2 2026-07-06; v0.2.1–v0.2.4 additions 2026-07-09/10). Changes via [proposals/](proposals/) — see [CHANGELOG.md](CHANGELOG.md). **Normative.** Additive over [v0.1](chp-v0.1.md); refines the
outcome model (§8) and denial semantics (§9) of v0.1 and the governance
vocabulary of [chp-governance-v0.2.md](chp-governance-v0.2.md).

Key words MUST, SHOULD, MAY per RFC 2119.

## 1. Purpose

v0.1 specifies *what* an invocation outcome and a denial are; the governance doc
specifies the *vocabulary* (reserved denial codes, event types). Neither pins the
**order** in which a host applies its gates, nor the **exact trigger predicate**
for each reserved denial code. That order is observable — two hosts that gate in
a different order emit *different evidence chains for identical input* — so it
MUST be normative for independent implementations to agree. This document is the
authoritative source for both the gate ordering and each reserved code's trigger.

A conforming host processes every invocation through the gates below **in this
order**. The first gate whose condition holds determines the outcome and the host
MUST stop (no later gate runs, no handler executes). This ordering is why, e.g., a
`policy_blocked` invocation emits **no** safety-assessment events: policy (gate 6)
precedes safety (gate 10).

"Processed" means the invocation reached the pipeline. Every processed invocation
— including a denial or skip — produces evidence and, over the HTTP binding,
returns **HTTP 200** with the outcome in the body (see
[chp-http-binding.md](chp-http-binding.md) §1). Transport-level rejections
(malformed request, failed auth, unknown route) are *not* processed invocations.

For **deferred execution** (background jobs, queues): the gates run once, at
submit time, against the submitting invocation — so the deferred execution's
evidence MUST ride the submitting correlation with a causal edge
([chp-v0.2.md](chp-v0.2.md) §7, "Deferred execution"). A fresh correlation
would detach the executed work from the invocation the gates governed.

## 2. The pipeline (MUST be applied in this order)

For each gate: **Trigger** is the exact predicate; **Outcome** is the
`InvocationResult.outcome`; **Code** is the reserved `DenialReason.code` (n/a for
non-denials); **Events** are the evidence events emitted for that gate.

**Before the pipeline.** One reserved code is emitted *before* gate 1 and never
by a host's pipeline: `host_unreachable` — a **routing intermediary** could
reach no owner of the capability, so the invocation never arrived at any host
(chp-v0.2.md §11, chp-http-binding.md §3). It is still a PROCESSED denial
(HTTP 200, evidence at the intermediary), just not a pipeline gate.

| # | Gate | Trigger (exact predicate) | Outcome | Code | `retryable` | Events emitted |
|---|------|---------------------------|---------|------|-------------|----------------|
| 1 | Non-empty id | `capability_id` is missing, empty, or whitespace-only | `denied` | `capability_not_found` | false | `execution_denied` |
| 2 | Resolution | No registered capability matches `(capability_id, version)`. If `version` is null and exactly one version is registered, it resolves; an ambiguous unversioned match does **not** resolve | `denied` | `capability_not_found` | false | `execution_denied` |
| 3 | Enabled | The resolved capability is registered but **disabled** | **`skipped`** | `capability_disabled` | n/a | `execution_skipped` |
| 4 | Mode | `envelope.mode` ∉ `descriptor.modes` | `denied` | `unsupported_mode` | false | `execution_denied` |
| 5 | Mandate | The envelope presents a `mandate` (see §3) | `denied` when it fails | `mandate_invalid` **or** `policy_blocked` | false | `execution_denied`; a VALID mandate denies nothing — it rebinds the subject |
| 6 | Policy | A `PolicyConfig` is active and blocks (see §4) | `denied` | `policy_blocked` | false | `execution_denied` |
| 7 | Invariants | A host-enforced invariant with `failure_behavior="deny"` does not hold for the payload | `denied` | `invariant_failed` | false | `execution_denied` (carries `invariant_id`) |
| 8 | Autonomy | An `AutonomyProfile` budget/tier gate fires (see §5) | `denied` | `budget_exceeded` **or** `approval_required` | see §5 | a governance event **then** `execution_denied` |
| 9 | Input schema | `descriptor.input_schema` is set and the payload fails JSON-Schema validation | `denied` | `input_schema_validation_failed` | false | `execution_denied` (SHOULD carry `schema_id`, `path`) |
| 10 | Safety | A safety evaluator is configured and a guardrail blocks (see §6) | `denied` | `safety_blocked` | false | assessment pair + guardrail/block events **then** `execution_denied` |
| 11 | Execute | All gates passed | `success` \| `failure` | n/a | n/a | `execution_started` → `execution_completed` (success) \| `execution_failed` (handler raised) |

**Subtlety 1 — gate 3 is a skip, not a deny.** A disabled capability yields
outcome **`skipped`** and event `execution_skipped`, *not* `denied`. It carries
the `capability_disabled` code as descriptive metadata, but it is not a denial.
Implementers frequently get this wrong.

**Subtlety 2 — see §5** for the autonomy counting rule.

## 3. Gate 5 — Mandate (delegated authority)

When the envelope presents a `mandate` ([chp-v0.2.md](chp-v0.2.md) §10),
evaluate in this order; absent a mandate this gate is a no-op:

1. **Verify** the mandate offline — structure, header signature, principal
   attestation, and the validity window **at host time** (a host MUST NOT
   trust the client-asserted `requested_at`). When transport auth has already
   verified a caller identity, the mandate MUST name that caller as
   `delegate_id`. Any failure → deny `mandate_invalid` (`retryable: false` —
   an expired mandate never becomes valid; a new mandate is a new object).
   `details` SHOULD carry the per-check results and `mandate_id`.
2. **Scope** — if the resolved capability id is outside the mandate's `scope`
   (http-binding §2 grammar) → deny `policy_blocked` (the same semantics as an
   out-of-scope caller key).
3. **Bind** — a valid, in-scope mandate rebinds the envelope subject to
   `{id: <delegate_id>, type: "mandate", verified: true, mandate_id,
   principal: <principal host_id>}` before any later gate runs, so every
   evidence event attributes the work to the delegate acting under the
   principal's authority. A mandate **narrows and attributes — it never
   bypasses**: transport auth still gates the connection, and gates 6–10
   still apply to the invocation.

## 4. Gate 6 — Policy (evaluation order within the gate)

When a `PolicyConfig` is active, evaluate in this order; the first match blocks:
1. **Allowlist** — if `allowed_capability_ids` is set and the id is not in it → block.
2. **Blocked ids** — if the id is in `block_capability_ids` → block.
3. **Risk tier** — if `max_risk_tier` is set: the capability's effective risk
   (`descriptor.risk`; an unknown/absent tier is treated as `medium`) ordered
   above `max_risk_tier` under `low < medium < high < critical` → block.
4. **Block patterns** — if any `block_patterns` entry matches the payload
   (case-insensitive substring/regex per the pattern) → block.

A policy in `audit_only` mode records the decision as evidence but MUST NOT block
(the invocation proceeds to gate 7). A block at any step yields `policy_blocked`;
the `details` SHOULD identify which rule matched.

## 5. Gate 8 — Autonomy (budget + approval)

When `descriptor.autonomy` is set, evaluate in this order:
1. **`action_limit`** — count the `execution_started` events already recorded for
   this `correlation_id`. **Only `execution_started` counts** — denials, skips,
   and governance side-events do NOT. If the count ≥ `action_limit`: emit a
   `budget_exceeded` **event**, then deny `budget_exceeded` (`retryable: true`).
2. **`spend_limit`** — if `execution_started_count × spend_units ≥ spend_limit`:
   emit `budget_exceeded`, then deny `budget_exceeded` (`retryable: true`).
3. **`tier == "approval_required"`** — emit an `approval_requested` **event**,
   then deny `approval_required` (`retryable: true`).

The governance event MUST be emitted **before** the `execution_denied` event, so a
replay shows the budget/approval decision preceding the denial. `budget_exceeded`
and `approval_required` are `retryable` because the governing state can clear
(budget resets, approval is granted); all other reserved codes are non-retryable.

## 6. Gate 10 — Safety

When a safety evaluator is configured, it assesses **every** invocation that
reaches this gate (i.e. one that passed gates 1–9):
1. Emit `safety_assessment_started`, then `safety_assessment_completed` (carrying
   `level`, `score`, `approved`) — **on every such invocation**, whether or not it
   blocks. A signed safety verdict on every governed invocation is the point.
2. If a guardrail blocks: emit `safety_guardrail_triggered`, then
   `safety_action_blocked`, then deny `safety_blocked`.
3. If it permits: emit `safety_action_approved` and proceed to gate 11.

## 7. Conformance

A host that applies these gates out of order, emits a denial where a skip is
required (gate 3), miscounts the autonomy budget (§5.1), or omits a required
governance event is **non-conforming** even if each individual outcome looks
correct — because its evidence chain for a given input differs from the reference.
The `wire` conformance suite ([chp-http-binding.md](chp-http-binding.md) §5)
exercises gates 2, 3, 4, 5(mandate), 6(risk), 7, 8(budget+approval), 9, 10 and
the success/failure paths against the fixture profile
([conformance/FIXTURES.md](../conformance/FIXTURES.md)).
