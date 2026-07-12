# 0014: Gateway Exactly-Once — Cross-Owner Idempotent Replay

- **Status:** shipped (2026-07-11, spec v0.3.3)
- **Issue:** rad:f036ac6
- **Affects:** chp-v0.2.md §13 (a new **§13.2 "Gateway exactly-once"**; the §13 single-host-scope sentence now points to it) + §11 cross-ref. Canonical bytes: **none** — this is behavioral (a gateway-level result cache is serving state; the `replayed:true` marker already exists). No new statement kind, denial code, evidence type, schema, or test vector. Spec **v0.3.2 → v0.3.3**. **Python-gateway-only** (a gateway is a §11 routing concept; the single-host reference is unaffected).

## Problem

§13 idempotent replay (proposal 0008) dedupes **per host** — "cross-owner dedupe
at a gateway is deliberately out of scope." A gateway (the reference
`MultiHostRouter`) failing over between owner hosts can still **double-execute**:

- The router reuses ONE `invocation_id` across owner-failover attempts *within a
  single call*, so an owner that already executed replays via **its own** gate 0
  — but only for a retry landing on the **same** owner. A cross-owner failover
  (owner A raises `ConnectionError` → the gateway tries owner B) re-executes on a
  peer whose separate result cache never saw that id.
- Worse, the gateway **mints its own `invocation_id`** and drops the client's, so
  its dedupe is scoped to one `ainvoke` call in one process. A client *retry*, or
  a gateway *restart*, mints a different id — the per-owner §13 cache cannot
  dedupe, and an owner double-executes.

## Design

A gateway maintains a **result cache keyed by the client's `invocation_id` that
spans owners** — the distributed-cache deferral, done properly. The machinery
already exists: the gateway holds a `SQLiteEvidenceStore` (used for routing
events) whose `record_result` / `lookup_result` (the §13 `invocation_results`
table) are simply never called on the router path. Give the router the same
gate 0 a host has:

- **Preserve the client's `invocation_id` through the gateway.** The gateway
  reads the incoming envelope's `invocation_id` (client-supplied, or minted at
  ingress — always present) and **uses it end-to-end** (client → gateway →
  owner) instead of minting a fresh one, keeping the single-envelope-across-
  failover property.
- **Gate 0 before routing.** `lookup_result(invocation_id)`; on a hit, rebuild
  the `InvocationResult` with `replayed:true` and return **without routing** — no
  owner executes. A gateway that has served an id once never routes it again.
- **Record on a definitive outcome.** On a processed result (success/failure/
  final denial), `record_result(invocation_id, result)` — first-write-wins,
  TTL-bounded (`CHP_RESULT_CACHE_TTL_S`), spanning owners AND gateway restarts
  (the store is persistent). A **retryable** `host_unreachable` denial is NOT
  cached — caching a transient unreachable would wedge the id permanently.
- **Serving, never evidence.** The cache is serving state (never chained); a
  cache hit *suppresses* execution and emits no lifecycle events. No new
  `gateway_*` evidence type — only a gateway idempotent-replay metric.

This makes a client retry exactly-once across owner **selection, failover, and
gateway restart** — the tractable, common case. The owner still runs its own §13
gate 0 on the forwarded id (belt-and-suspenders for the same-owner retry); the
gateway cache is the cross-owner layer.

## Compatibility

Fully behavioral and additive: no canonical object, denial code, evidence type,
schema, or test vector changes; every published vector is byte-identical. A
gateway with no store configured simply skips the cache (best-effort, like the
per-host lookup). The `replayed:true` marker on a gateway replay is the same
byte-stable field §13 already defines. The single-host reference host is
unchanged; only the §11 routing gateway gains the cross-owner cache. No TS
parity — the TS host is a mesh *member* (an owner), never a gateway.

Deferred by design: the honest §11 residual — an owner that executed but whose
response was lost *before reaching the gateway* leaves the gateway unable to
cache what it never saw, so a failover to a different owner still double-
executes (true exactly-once there needs owner-side coordination); owner-pinned
or shared cross-owner caches; multi-gateway distributed dedupe + cache
replication; cache eviction beyond the TTL window.

## Shipped as

- Spec: chp-v0.2.md **§13.2 "Gateway exactly-once"** + the §13 single-host-scope
  sentence now points to it; status line **v0.3.3**; CHANGELOG **[0.3.3]**. No
  schema change
- Bytes: no canonical object, denial code, evidence type, or test vector — every
  published vector byte-identical (`git diff spec/test-vectors/` empty)
- Guards: `spec_defines_gateway_exactly_once` (alignment 75→76); mesh conformance
  **8→9** (`check_mesh_exactly_once`: a pinned client `invocation_id` replays at
  the gateway with no owner re-execution, and STILL replays after the serving
  owner is killed while a fresh id is `host_unreachable`)
- Implementation (Python-gateway-only): `MultiHostRouter.ainvoke` gains a client-
  `invocation_id` gate-0 (`lookup_result` → replay-without-routing) + `record_result`
  on a definitive owner outcome (routing denials not cached); `ainvoke_envelope`
  forwards the client id; the id transits client → gateway → owner unchanged;
  `host.lookup_recorded_result` extracted as the shared rebuild; reuses the
  `record_idempotent_replay` metric. No TS changes (TS host is a member, not a gateway)
- Refinement vs proposal: none — landed as designed; the lost-response-before-
  gateway residual + owner-pinned/shared caches + multi-gateway dedupe stayed named
