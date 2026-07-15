# 0036: Richer Policy Decision Vocabulary + Versioned Decision Records

- **Status:** shipped (spec v0.9.0, chp-core 0.46.0, npm alpha.40)
- **Issue:** rad:727ab580
- **Affects:** chp-governance-v0.2.md §2 (two new reserved codes) + §3.1 (the decision
  vocabulary) + chp-invocation-pipeline.md gate 6. **Two NEW reserved denial codes**
  (`escalation_required`, `evidence_required`) registered across the 4 sites. **Additive:**
  a block-pattern with no `decision` means `deny`, exactly as pre-0036; no wire break.
  Spec **v0.8.8 → v0.9.0**. M2 / GAP 3 of the portfolio substrate mandate. Public
  (protocol vocabulary) per ADR-0002.

## Problem

The policy engine is **binary** — `evaluate_policy` returns `should_block: bool` + a
free-text `reason`. A host can only allow or deny; it cannot express "a human must
approve," "escalate to a higher authority," "provide more evidence," or "run this only in
a sandbox." And a denial records nothing structured — no decision label, no matched-rule
id, no policy version — so a refusal is not attributable to a *named, versioned* rule.
This is substrate gap GAP 3.

## Design

**Decision vocabulary.** The policy gate renders one of six decisions:
`allow` / `deny` / `requires_approval` / `requires_escalation` / `requires_more_evidence` /
`sandbox_only`. Coarse rules (allowlist, block-id, `max_risk_tier`) render `deny`; a
**block-pattern** rule MAY declare any decision (default `deny` → backward-compatible).

**Reserved-code mapping** at the governance gate: `deny`→`policy_blocked`,
`requires_approval`→`approval_required`, `requires_escalation`→**`escalation_required`**
(new), `requires_more_evidence`→**`evidence_required`** (new), `sandbox_only`→
`policy_blocked` (**fail-closed** — there is no sandbox execution mode yet, so a decision
the host cannot honor must not silently proceed; the constrained-execution machinery is a
deferral). `requires_approval` / `requires_escalation` / `requires_more_evidence` are
**retryable** — the caller can take the required next action and re-invoke.

**Versioned decision record.** Every non-`allow` denial carries in `details`:
`{decision, matched_rule, policy_version, explanation, required_next_action}`. The policy
file's `version` is threaded through; `matched_rule` names the rule that fired
(`allowed_capability_ids`, `block_capability_ids:<id>`, `max_risk_tier:<tier>`, or
`block_pattern:<cap>.<field>`). `audit_only` records the decision but never blocks
(advisory).

## Compatibility

Additive. A pre-0036 policy file (no `decision`, no `version`) behaves identically — every
rule renders `deny`, exactly as before. The two new reserved codes are additive registry
entries. Three implementations (Python, TS host, stdlib `verify.mjs`) agree via
`spec/test-vectors/policy-decision.json`. `sandbox_only`'s real constrained execution and
an always-on policy-decision *evidence event* (vs. the current denial-details record) are
deferrals.

## Shipped as

- **Spec:** chp-governance-v0.2.md §2 (+2 codes) + §3.1 (vocabulary); pipeline gate 6.
- **Codes:** `escalation_required` + `evidence_required` across RESERVED_CODES, the denial
  schema examples, the governance table, the runtime, and the pipeline/security-model lists.
- **Vectors:** `spec/test-vectors/policy-decision.json` (7 decision+code KAT cases).
- **Guards:** `spec_defines_policy_decisions` + `policy_decision_vector_verifies` (plus the
  existing reserved-code sync guards now cover the two new codes).
- **Implementations:** Python (`policy.py` decision + record, `host.py` `_POLICY_DECISION_CODE`
  mapping + decision record on the denial), TS host (`checkPolicy` mirror + `PolicyConfig`
  block-patterns/version/decision), `verify.mjs` matcher. Test: `test_policy_decisions.py`.
