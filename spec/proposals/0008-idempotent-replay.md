# 0008: Idempotent Invocation Replay — Making Retries Safe

- **Status:** shipped (2026-07-11, spec v0.2.7)
- **Issue:** rad:1a224d2
- **Affects:** chp-v0.2.md (new §13), chp-invocation-pipeline.md (gate 0 note), chp-http-binding.md (idempotency-key note); canonical bytes: **no changes** (no new statement kind, no new denial codes, no new evidence types; `InvocationResult` gains an OPTIONAL `replayed` field omitted when false — every existing result is byte-identical)

## Problem

Retry is deliberately caller-side (§11: "retry stays with the caller"), but the
caller's retry is unsafe by documented caveat: a connection that drops AFTER
the host executed leaves the caller unable to distinguish "never ran" from
"ran, response lost" — retrying may double-execute non-idempotent work. The
reference client ships `retries=0` for exactly this reason, and the gateway's
owner-failover regenerates a fresh `invocation_id` per attempt, so even the
mesh's own reliability machinery cannot retry safely. Meanwhile the
idempotency key already exists: every invocation carries an `invocation_id`,
every host records it, and the evidence store indexes it. What's missing is
the semantics.

## Design

**A host that has already recorded an `invocation_id` MUST NOT re-execute it.
It returns the recorded result.**

- **Scope**: all processed outcomes — `success`, `failure`, `denied`,
  `skipped`. A replayed denial is the same denial; gates do not re-run (their
  decision is part of what was recorded). Streaming invocations are excluded
  (named deferral).
- **The key**: the envelope's `invocation_id` — no new header, no new field.
  A caller that wants retry-safety sends the SAME `invocation_id` on every
  attempt; a caller that wants a fresh execution sends a fresh id (the
  existing default). Uniqueness scope is the single host: replay happens only
  on the host that served the original.
- **The result cache is serving state, never evidence.** The evidence chain
  remains the audit record; the recorded result (including the handler's
  `data`, which evidence deliberately does not persist) lives in a
  host-local, window-bounded cache (reference: an `invocation_results` table
  beside `correlation_heads`, default retention 24h). After the window, a
  duplicate id executes fresh — idempotency is a bounded-window guarantee,
  stated plainly.
- **Marking**: a replayed response carries `"replayed": true` on the
  `InvocationResult` (omitted when false — additive, byte-stable). No
  lifecycle events are appended for an execution that did not happen; the
  reference implementation exposes `chp_idempotent_replays_total`. A
  reserved `invocation_replayed` evidence type is a named deferral.
- **Retention interaction**: purging a correlation MUST also drop its cached
  results — a lawfully purged invocation must not remain replayable.
- **Security considerations**: replay is not a new disclosure — the result
  was already returned once, and every replay passes the same transport auth
  (and per-caller key scope) as any invocation. A caller who can present a
  guessed `invocation_id` receives the cached result only if it can also
  authenticate; ids are 128-bit random by construction. Hosts MAY bind
  replay to the original caller identity (stricter-than-spec, allowed).
- **Client + gateway (reference)**: the client retry loop generates ONE
  `invocation_id` before the first attempt; the gateway failover loop reuses
  one envelope across candidate owners — the §11 caveat ("a mid-flight drop
  may have executed") is neutralized against 0008-conformant hosts.

## Compatibility

Fully additive: a host without replay support remains conformant at the
prior tier (the new wire check is what claims replay support); callers that
never reuse ids see identical behavior. No canonical-byte change (the
`replayed` field is omitted when false); published vectors byte-identical;
no new denial codes or evidence types. Wire conformance grows 21→22.

Deferred by design: streaming replay, gateway-level dedupe (replay across
owners), a distributed/cross-host result cache, the `invocation_replayed`
evidence type, and caller-identity-bound replay as a normative requirement.

## Shipped as

- Spec: chp-v0.2.md **§13 "Reliability — Idempotent Replay"**; pipeline
  **gate 0**; http-binding idempotency-key note; CHANGELOG **[0.2.7]**
- Bytes: zero changes — no new statement kind, denial code, evidence type,
  schema, or vector; `replayed` omitted-when-false (verified byte gate)
- Guards: `spec_defines_idempotency` (alignment 63→64); wire suite **21→22**
  (`check_idempotent_replay`: recorded-data replay + marker + single
  execution in evidence, denial replays as the same denial, fresh ids
  execute fresh — both reference hosts 22/22 first try)
- Implementations: Python `invocation_results` serving table (first-recorded
  wins, lazy TTL sweep, `CHP_RESULT_CACHE_TTL_S`) + gate 0 in `_prepare` +
  best-effort recording on all processed outcomes + purge cascade at all
  three compliance delete sites + `chp_idempotent_replays_total`; client
  retry loop + gateway failover thread ONE stable `invocation_id`
  (previously: no id / fresh id per attempt); TS host in-memory dedupe map
- Refinement vs proposal: none — landed as designed; deferrals stayed as
  named (streaming replay, gateway dedupe, distributed cache,
  `invocation_replayed` evidence type)
