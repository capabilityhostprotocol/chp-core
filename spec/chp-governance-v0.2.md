# Capability Host Protocol — Governance Vocabulary (v0.2)

Status: draft. **Additive** over [v0.1](chp-v0.1.md). Governance is CHP's
differentiator: the boundary doesn't just record *what an agent did*, it records
*what governed it* — denials, risk tiers, autonomy budgets, human approval,
safety guardrails — as first-class, correlated evidence on the same signed plane.
v0.1 left this vocabulary implementation-defined; this document promotes it to
**normative, interoperable** surface so two independent hosts agree on what
`denied`, `high` risk, or `approval_required` mean.

Key words MUST, SHOULD, MAY per RFC 2119. (This supersedes the private-spec
section numbers — `§7.2`, `§8.5`, `§8.6`, `§9.3`, `§9.5` — cited in earlier code
docstrings; those referred to an unpublished draft. This is the published home.)

## 1. Scope

Normative here: the denial-code registry (§2), risk-tier semantics (§3), the
governance event-type vocabulary (§4), and the namespacing convention that keeps
extensions from colliding with the core (§5). All build on the v0.1 outcome model
(`success`/`failure`/`denied`/`skipped`) and the `execution_*` core events.

## 2. Denial-Code Registry

A `denied` outcome MUST carry a `DenialReason` (`schemas/denial-reason.schema.json`)
with a stable `code`, human-readable `message`, and `retryable` flag. When a
denial matches one of the reserved conditions below, a conforming host **MUST**
emit the corresponding reserved code (not a synonym) — this is what lets a
consumer branch on `code` across implementations.

The **exact trigger predicate** for each code, and the **order** in which a host
applies the gates that produce them, are normative in
[chp-invocation-pipeline.md](chp-invocation-pipeline.md). That ordering is
observable (a `policy_blocked` invocation emits no safety events), so an
implementation MUST follow it — the table below is the vocabulary; the pipeline
doc is the authoritative trigger + ordering. Note `capability_disabled`
accompanies a **`skipped`** outcome, not `denied` (pipeline gate 3).

| Reserved code | Meaning | `retryable` |
|---|---|---|
| `capability_not_found` | No capability with that id (or version) is registered. | false |
| `capability_disabled` | Registered but disabled by the host. | false |
| `unsupported_mode` | The requested invoke `mode` isn't supported. | false |
| `policy_blocked` | A `PolicyConfig` rule blocked it — a block-pattern match **or** the capability's risk tier exceeding `max_risk_tier` (§3). `details` SHOULD name the rule. | false |
| `input_schema_validation_failed` | The payload failed the capability's declared input schema. | false |
| `invariant_failed` | A declared invariant did not hold. `invariant_id` SHOULD be set. | false |
| `budget_exceeded` | An `AutonomyProfile` budget (calls / tokens / cost) was exhausted (§4.1). | true |
| `approval_required` | A human-approval gate is unsatisfied (§4.1). | true |
| `safety_blocked` | A safety guardrail blocked the invocation (§4.2). | false |

`retryable` is normative advice to the caller: `budget_exceeded` and
`approval_required` describe transient governance state that may clear (budget
resets, approval granted); the rest describe stable rejections that will recur
for the same input. `RESERVED_CODES` in `types.py:DenialReason` is the source of
truth; the schema examples and this table MUST match it (guarded by
`protocol_checks`).

A host MAY deny for a reason outside this set, but the `code` MUST then be
reverse-DNS namespaced (§5) — e.g. `com.acme.quota_exceeded` — never a bare
lowercase token that could collide with a future reserved code.

## 3. Risk-Tier Semantics

A capability MAY declare a risk tier; a `PolicyConfig` MAY cap the allowed tier
via `max_risk_tier`. The tiers are **totally ordered**
`low < medium < high < critical` (`policy.py:RISK_ORDER = {low:0, medium:1,
high:2, critical:3}`). An invocation is `policy_blocked` when the capability's
effective tier orders **above** the policy's `max_risk_tier`. A capability with
an unknown/absent tier is treated as `medium` for this comparison.

The tiers denote **blast radius if the invocation misbehaves**, not likelihood:

- `low` — read-only or trivially reversible; no external side effects (a query, a hash).
- `medium` — writes to local/owned state, or reversible external calls (a DB write, an idempotent API call). **Default** for an unclassified capability.
- `high` — non-trivially-reversible external side effects (send a message, spend money, mutate shared infra).
- `critical` — irreversible or wide-blast-radius (delete data, deploy, financial transfer, anything a human would want to sign off first).

`high`/`critical` are the tiers a host SHOULD gate behind autonomy budgets or
human approval (§4.1).

## 4. Governance Event Vocabulary

Governance decisions are recorded as evidence events on the same chain as
`execution_*`, so a replay shows the decision *and* its context in order. The
following event-type families are reserved and normative.

### 4.1 Autonomy & Approval (`AUTONOMY_EVIDENCE_TYPES`)

- `budget_exceeded` — an autonomy budget was hit (pairs with the `budget_exceeded` denial).
- `approval_requested` — the host paused an invocation pending human approval.
- `approval_granted` / `approval_denied` — the human decision, correlated to the request.

A host enforcing an `AutonomyProfile` MUST emit `approval_requested` before an
`approval_required` denial or a paused execution, and exactly one of
`approval_granted`/`approval_denied` when the decision resolves.

### 4.2 Safety (`SAFETY_EVIDENCE_TYPES`)

- `safety_assessment_started` / `safety_assessment_completed` — a guardrail evaluation ran.
- `safety_guardrail_triggered` — a guardrail matched.
- `safety_action_blocked` / `safety_action_approved` — the guardrail's decision.

A host with a configured safety evaluator MUST emit the assessment pair
(`safety_assessment_started` / `safety_assessment_completed`) around every
governed invocation and a `safety_action_approved` or, when a guardrail blocks,
`safety_guardrail_triggered` + `safety_action_blocked` for its decision — so the
safety verdict is auditable alongside the execution it governed. A guardrail
block denies with the reserved `safety_blocked` code (§2). The assessment is
recorded even when it permits the action: a signed safety verdict on every
invocation is the point, not only the blocks.

### 4.3 Incident & Compliance

`INCIDENT_EVIDENCE_TYPES` (`incident_opened`, `incident_escalated`,
`incident_remediation_applied`, `incident_resolved`, `incident_closed`,
`incident_trigger_fired`) and `COMPLIANCE_EVIDENCE_TYPES`
(`retention_policy_applied`, `evidence_purged`, `evidence_redacted`,
`compliance_report_generated`) are reserved with their lifecycle orderings as
named. Redaction/purge events are how retention (v0.2 §4) stays auditable: the
act of removing evidence is itself evidence.

### 4.4 Host Identity (`IDENTITY_EVIDENCE_TYPES`)

- `key_generated` / `key_rotated` / `key_revoked` — the host's signing-key
  lifecycle (chp-v0.2.md §3.2), including the rotation continuity link
  (`old_key_id`/`new_key_id`).
- `identity_anchored` — an external trust root was bound to the key (§3.1).

These are **host-self** events: they describe the host, not an invocation, and
ride the host's own hash chain under correlation `host-identity-<host_id>` —
which thereby serves as the host's key-transparency log.

## 5. Namespacing & Extension

To let independent implementations extend the vocabulary without colliding:

- **Reserved core.** All event types published here and in v0.1 (the
  `execution_*` core and the `*_EVIDENCE_TYPES` families), all reserved denial
  codes (§2), and the `chp.*` capability-id prefix are **reserved**. An
  implementation MUST NOT redefine their meaning.
- **Vendor extensions.** Custom event types, denial codes, and capability ids
  MUST be **reverse-DNS namespaced** under a domain the author controls —
  `com.acme.deploy_requested`, `com.acme.quota_exceeded`,
  `com.acme.billing.charge`. This guarantees two vendors can't silently collide
  on a bare name like `task_completed`.
- A bare (non-namespaced) name that is not in the reserved set is **undefined**;
  a strict consumer MAY reject it. This is a convention, not a central registry —
  no IANA-style allocation is required.

## 6. Conformance

A host that emits governance evidence MUST: use reserved denial codes for
reserved conditions (§2); order risk tiers per §3; emit the approval/safety event
sequences in §4 when it runs those subsystems; and reverse-DNS namespace every
extension (§5). `protocol_checks` asserts the runtime, schema, and this document
agree on the reserved denial set.
