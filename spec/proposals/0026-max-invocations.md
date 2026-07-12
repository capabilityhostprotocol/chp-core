# 0026: `max_invocations` Enforcement + Delegation-Lifecycle Events

- **Status:** shipped (spec v0.7.1, chp-core 0.34.0, npm alpha.25)
- **Issue:** rad:5b66e976
- **Affects:** chp-v0.2.md §10 (a mandate gains an optional **signed
  `max_invocations`** cap; the mandate gate counts distinct invocations per
  `mandate_id` and denies the new **`mandate_exhausted`** code past the cap) +
  chp-invocation-pipeline.md gate 5 + the governance/security/reserved-names code
  registries. **Additive** — `max_invocations` is omit-when-empty (unlimited when
  absent) and lives in the signed header, so every existing mandate is
  byte-identical. Spec **v0.7.0 → v0.7.1**.

## Problem

A mandate (0002) already expresses *who* may invoke *what* until *when* — but not
*how many times*. `max_invocations` has been the most-repeated authority deferral,
named in 0002, 0007, and 0009 and in the security model. Today a delegated grant is
unbounded in count for its whole validity window; a principal cannot hand out a
one-shot or N-shot authority. Nothing enforced a cap because the mandate carried no
count field and the gate did no counting.

## Design

**A signed cap.** `build_mandate(..., max_invocations=N)` adds an optional
`max_invocations` to the mandate and — critically — to the **signed header**
(`mandate_header`), omit-when-absent exactly like the sub-delegation `depth`/
`parent_id` fields. Living inside the signature, the cap cannot be raised or
stripped by the delegate or a relay. A sub-mandate (0009) MAY only **lower** it
(attenuation, alongside narrowing scope and shortening the window).

**Delegate-side counting at the gate.** The mandate gate (pipeline gate 5), after
verifying the mandate and its scope, counts the **distinct `invocation_id`s** the
host has already recorded under this `mandate_id`. The count is keyed on
`invocation_id` — the same key idempotent replay (0008) uses — so a **replayed**
invocation never double-counts (and replay short-circuits before the gate anyway;
the dedup is defense in depth). If the count ≥ `max_invocations` for a *new*
invocation → deny **`mandate_exhausted`** (`retryable: false` — the grant is spent;
`details` carries `used` + `max_invocations`); otherwise the host records this use
and proceeds. Absent `max_invocations` the step is a no-op. The counter is
per-delegate-host — a shared cross-host counter is out of scope (a mandate used
against two hosts is counted independently at each).

Persistence: a `mandate_usage(mandate_id, invocation_id)` table with a composite
primary key (INSERT-OR-IGNORE), so `count = COUNT(*) WHERE mandate_id = ?` is the
authoritative used-count and re-recording the same use is a no-op.

**`mandate_exhausted`** joins `DenialReason.RESERVED_CODES` (and the denial schema,
the governance + security-model + pipeline specs, and the generated
`reserved-names.md` + `reserved.ts`) — the standard new-reserved-code discipline.

**Delegation-lifecycle events.** The `delegation_created / accepted / completed /
rejected` event types (the `chp-adapter-delegation` foundation, named in 0002 and
0009) are promoted to recognized evidence types so a delegated hand-off is a
first-class, chainable record rather than adapter-local state.

## Compatibility

Additive and non-destabilizing. `max_invocations` is omit-when-absent in both the
mandate and its signed header, so every existing mandate, sub-mandate, and vector
is byte-identical; a mandate without the field is unlimited as before. The new
reserved code is additive to the closed vocabulary (the guard set already enforces
its presence across the registries). A **patch** bump (v0.7.1): it completes an
existing authority object rather than adding a new artifact family.

## Deferred by design

Rate-limit **windows** (N per hour, vs a lifetime count); a **shared cross-host**
counter (a mandate used against a mesh of delegate hosts, counted globally — needs
the distributed-cache infrastructure the exactly-once deferrals name); reclaiming
count on a failed execution (an exercised-but-failed invocation still consumes a
use — the authority was spent); per-capability sub-caps within one mandate.

## Shipped as

- **Spec v0.7.1** — chp-v0.2.md §10 (`max_invocations` cap + `mandate_exhausted`),
  chp-invocation-pipeline.md gate-5 counting step; `mandate_exhausted` added to
  the denial schema + governance/security-model specs + `reserved-names.md`.
- **chp-core 0.34.0** — signed `max_invocations` in `build_mandate`/`mandate_header`;
  `store.mandate_usage` table + `count_mandate_uses`/`record_mandate_use`
  (composite-PK, replay-safe); the mandate gate denies `mandate_exhausted` past
  the cap. Also carries the Track B Linux/WSL secrets fallback.
- **npm alpha.25** — chp-sdk `mandateHeader` covers `max_invocations` (byte-parity).
- **Vectors + guards** — `mandate-capped.json` (verified in Python + TS SDK +
  `verify.mjs`; a raised cap breaks the signature); conformance `check_mandate_gate`
  case 5 (cap=2 denies the 3rd); `spec_defines_max_invocations` +
  `capped_mandate_vector_verifies` (alignment 99 → 101).

Deferred (unchanged): rate-limit windows, shared cross-host counters, reclaiming a
count on a failed execution, per-capability sub-caps.
