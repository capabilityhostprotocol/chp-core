# 0052: Absolute invocation deadlines

- **Status:** shipped
- **Issue:** rad:fce30b1
- **Affects:** spec (chp-invocation-pipeline §gates, chp-application-contract), schemas (invocation envelope), wire routes (envelope field; propagated to sub-invocations), canonical bytes? **yes — additive, omit-when-None**

## Problem

CHP has no *time* deadline. The invocation envelope carries `requested_at` (a
wall-clock stamp) but nothing that bounds how long work may remain useful, and the
only "budget" today is the AutonomyProfile budget (calls / tokens / cost), which is
a spend limit, not a clock. Two server requirements depend on a time deadline and
cannot be satisfied without it:

- **CAP-005** — *absolute* deadlines MUST propagate across local and remote hops
  without resetting the caller's deadline.
- **CAP-006** — a server MUST reject or stop work when no valid deadline budget
  remains.

"No valid deadline budget remains" is unenforceable while there is no deadline to
check, and a per-hop *relative* timeout (e.g. `timeout_ms`) cannot express CAP-005
because each hop would re-base it. The primitive must be an **absolute instant** so
it survives fan-out and remote hops unchanged.

## Design

**Envelope field (additive).** Add one optional field to the invocation envelope:

```
deadline: str | None = None   # RFC3339 / ISO-8601 UTC instant, e.g. "2026-09-15T21:00:00Z"
```

- Absolute, not relative: it is the wall-clock instant after which the result is no
  longer wanted. A hop never re-bases it (CAP-005).
- `None` = today's behavior (no deadline). Omit-when-None on serialization keeps the
  canonical bytes **byte-identical** to pre-0052 for every envelope that sets no
  deadline (the established additive pattern: cf `mandate`, `actor`, `binding`).

**Admission gate (new).** Add a gate to the `_prepare` pipeline
(`spec/chp-invocation-pipeline.md`), evaluated **before execution** and before any
consequential effect:

- If `deadline is not None` and `now > deadline + skew_allowance`, the invocation is
  a **processed denial** with `code = "deadline_exceeded"` — the work never runs, and
  the denial is evidenced like any other (it is a denial, not a `failure`).
- `skew_allowance` ties to **TIME-003** (known clock-skew bounds): comparison uses the
  authoritative clock-skew allowance rather than a bare `>` so a small skew does not
  spuriously deny. Where clock health is degraded past the point of a safe comparison
  (**TIME-006**), the gate fails closed (deny) for consequential capabilities.
- Placement: after identity/mandate verification, before grant/dispatch — same tier as
  `max_invocations` (0026), so a stale request is refused cheaply and uniformly.

**Propagation (CAP-005).** When a handler makes a sub-invocation through the governed
context (`ctx.ainvoke`), the child envelope **inherits the parent deadline unchanged**.
The deadline is copied verbatim (absolute instant), never recomputed from a remaining
duration, so a 3-hop chain shares one end-to-end budget. A child MAY carry a *tighter*
deadline (earlier instant) but MUST NOT carry a later one than its parent (a hop cannot
extend the caller's budget); a later child deadline is clamped to the parent's.

**Denial vocabulary.** `deadline_exceeded` joins the processed-denial codes
(`spec/proposals/0036-policy-decision-vocabulary.md`); it is distinct from
`budget_exceeded` (autonomy spend) and `max_invocations` (fan-out count).

**Outcome semantics.** A deadline that expires *before* admission is a denial
(work never ran). A deadline that expires *during* a long execution is out of scope
for this proposal (cooperative cancellation is EFF/cancellation territory, EFF-007,
BLOCKED_UPSTREAM); 0052 governs admission-time rejection only, which is exactly what
CAP-006 requires ("reject OR stop work when no valid budget remains" — reject at the
gate).

## Compatibility

- An implementation that ignores `deadline` remains conformant at the pre-0052 wire:
  envelopes that set no deadline are byte-identical, and a peer that never sets a
  deadline never triggers the gate.
- Byte-compat regression gate: the existing canonical-bytes vector suite gains a
  case asserting `deadline=None` serializes identically to a pre-0052 envelope, and a
  case asserting a set deadline round-trips.
- New conformance check (`conformance/`): a NORMATIVE case that an envelope whose
  `deadline` is in the past is denied `deadline_exceeded` before execution and records
  no effect; and a REFERENCE case that a sub-invocation inherits the parent deadline.

## Shipped as (Python; 2nd-impl parity tracked separately)

- Spec: chp-invocation-pipeline.md (deadline gate note, budget tier), chp-governance-v0.2.md
  + chp-security-model.md (reserved code `deadline_exceeded`), denial-reason.schema.json
  (code example). Reserved-code 4-way sync (runtime/schema/governance/pipeline) green via
  protocol_checks + test_security_model.
- Implementation: chp-core — additive `deadline` envelope field (omit-when-None →
  byte-identical, `_validated_deadline` at the trust boundary), `temporal.deadline_exceeded`
  (skew-aware, fail-closed), the `deadline_exceeded` admission gate in `_prepare` (budget
  tier, before execution), and verbatim propagation via `LocalCapabilityHost.ainvoke(deadline=)`
  inherited by `InvocationContext.ainvoke`.
- Tests: packages/python/tests/test_deadline.py (gate, byte-compat, validation, propagation,
  fail-closed helper); packages/chp-server/tests/conformance/test_deadlines.py (CAP-005/006
  over the wire). chp-core 1549 pass (1 worktree sync-clean artifact); chp-server 114 pass.
- **Deferred within this proposal:** 2nd-impl (chp-sdk/chp-host-ts) parity + spec/test-vectors
  entries for the set-deadline round-trip — additive follow-ups; the Python wire is byte-identical
  for deadline-absent envelopes so existing vectors are unaffected.
- Requirements: CHP-SRV-CAP-005/006 BLOCKED_UPSTREAM → VERIFIED.
