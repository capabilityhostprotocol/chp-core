# 0038: Adapter Operational Contract (timeout, retry, health)

- **Status:** shipped (spec v0.9.2, chp-core 0.48.0, npm alpha.42)
- **Issue:** rad:8150250b
- **Affects:** chp-v0.2.md §20 (new) + `CapabilityDescriptor` (additive `timeout_s`, `retry`)
  + `BaseAdapter.health()`. **No new object schema file, no new reserved denial code** (a
  timeout is an `execution_failed`, not a denial). **Additive:** a descriptor without the
  new fields is byte-identical. Spec **v0.9.1 → v0.9.2**. M3 / GAP 5 (the greenfield half —
  the publisher-signed install gate already shipped in proposal 0001). Public per ADR-0002.

## Problem

The adapter contract today is identity + capability discovery only. `BaseAdapter` declares
no `health()`; `CapabilityDescriptor` declares no `timeout` or `retry`. The mandate's §11
adapter declaration wants operational reliability — a health probe, a timeout, a retry
policy — none of which exists. (The publisher-signed **install gate** — the other half of
GAP 5 — is already shipped and normative in §9/proposal 0001; this proposal does not touch
it.)

## Design

**Declared, host-enforced timeout.** `descriptor.timeout_s` (a number, additive,
omit-when-absent). The host wraps the handler's result wait in it (Python `asyncio.wait_for`;
TS `Promise.race` against a timer). Exceeding it raises a `TimeoutError` caught as
`execution_failed` — a *failure*, not a governance denial, because the capability did not
refuse, it ran too long. **No new reserved code.** Omitted = unbounded (today's behavior).

**Advisory retry.** `descriptor.retry` = a `RetryPolicy{max_attempts, backoff_s, retry_on}`.
It is **advisory**: a caller or the routing gateway MAY honor it; the host does **not**
auto-retry (retrying is the caller's decision, and the mesh gateway already fails over). It
documents the capability's retry expectation for schedulers.

**Per-adapter health.** `BaseAdapter.health()` → `HealthStatus{status, detail?}` where status
is `healthy` / `degraded` / `unavailable`. An adapter overrides it to probe its backing
system; the default is `healthy`. `aggregate_health(adapters)` rolls a set up **worst-wins**,
and a `health()` that raises is reported `unavailable` (fail-safe — a broken adapter never
crashes the rollup). This is a self-report distinct from mesh/routing host health
(`host_marked_*`), so an operator can tell a broken adapter from an unreachable host.

## Compatibility

Additive; byte-identical when the fields are unused. No new denial code, no new schema file
(the two fields land on the existing capability-descriptor schema). Both reference hosts
enforce the timeout; the descriptor fields carry across Python + TS. Stream-path timeout
enforcement and a per-adapter `status()`/`cancel()` are deferred.

## Shipped as

- **Spec:** chp-v0.2.md §20.
- **Types:** `RetryPolicy`, `HealthStatus` (`types.py`); `timeout_s` + `retry` on
  `CapabilityDescriptor`; `BaseAdapter.health()` + `aggregate_health` (`adapters/__init__.py`);
  decorator params. Schema: `capability-descriptor.schema.json` (+`timeout_s`, `retry`,
  `RetryPolicy` def).
- **Enforcement:** host sync-path `asyncio.wait_for` (Python `host.py`) + `withTimeout`
  `Promise.race` (`chp-host-ts/host.ts`); TS descriptor fields (ts-types + host-ts).
- **Guards:** `spec_defines_adapter_contract` + `capability_schema_has_reliability_fields`.
- **Tests:** `test_adapter_contract.py` (timeout enforced, round-trip + omit-when-absent,
  retry validation, health default/override, aggregate worst-wins + fail-safe).
