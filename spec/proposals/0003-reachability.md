# 0003: Reachability Is Governed Evidence

- **Status:** shipped (2026-07-10, spec v0.2.4)
- **Issue:** rad:d64fffb
- **Affects:** chp-v0.2.md (new §11), chp-http-binding.md §3, chp-governance-v0.2.md §2 (denial code + retryable semantics), chp-invocation-pipeline.md §2 (before-the-pipeline note), `denial-reason` schema examples; canonical bytes: **no changes** (no new signed object, no envelope change)

## Problem

CHP's load-bearing rule — *processed means evidence, a denial is HTTP 200* —
stops at the routing layer. When a gateway can reach no owner of a capability,
the reference implementation raises through the HTTP handler as a **bare 500
with no evidence and no CHP error envelope**; when the capability is unknown
mesh-wide, the caller gets a misleading `400 Missing required field`. Router
health state (`unhealthy` marks, recheck windows, failovers) is an in-memory
dict that emits **no evidence, no metric, no log** — the mesh's reliability
story is invisible to the very evidence plane CHP exists to provide. And the
protocol has **no reachability vocabulary at all**: twenty reserved evidence
families and ten denial codes, none for transport.

`/export` and federated `/verify` already got this right (clean 503, never
silently partial; `/replay` discloses `partial` + `missing_hosts`). The hot
path — `/invoke` through a routing intermediary — did not.

## Design

**Reserved denial code `host_unreachable`** (`retryable: true` — the first
retryable *transport* code): emitted **only by a routing intermediary** when no
owner of the requested capability is reachable. It is a PROCESSED governance
decision — HTTP 200, outcome `denied`, evidence emitted — never a bare 5xx.
`details` SHOULD carry `{attempted_hosts, last_error, retry_after_s}`
(`retry_after_s` derived from the intermediary's recheck window, so the advice
is honest). A single host never emits it: the code marks "the mesh could not
reach the work", not "the work failed". Governance §2's retryable rule widens
from "transient governance state" to "transient state that may clear —
governance *or reachability*". The denial rides the existing
`execution_denied` event; no new denial event type.

**Reserved evidence family `ROUTING_EVIDENCE_TYPES`** =
`{host_marked_unhealthy, host_marked_healthy}` — self-events on the
**intermediary's own chain** (the §3.1 identity-events precedent), emission
strictly **transition-gated** (a success on an already-healthy host emits
nothing). When a transition happens while routing an invocation, the event
rides **that invocation's correlation** — a failover becomes replayable
in-context: `host_marked_unhealthy` followed by the next candidate's
`execution_started` IS the failover story, so no separate `routing_failover`
type is reserved (derivable = not reserved).

**Intermediary evidence posture:** an intermediary MUST return the processed
denial; it MUST record it (and its health transitions) as evidence when it
maintains an evidence store, and SHOULD maintain one. A storeless embedded
router remains conformant at the returned-denial floor. An intermediary with a
store merges its own events into stitched replay timelines, and its denials
land in the standard invocation metrics (`execution_denied` is already a
metrics event).

**Retry stays with the caller.** The intermediary's owner-failover is the
retry that helps; a client retry of `host_unreachable` only helps after the
recheck window, which `retry_after_s` communicates. The binding's
caller-retries stance (§4/4a) is unchanged; `retryable: true` finally has a
transport meaning for callers that act on it.

**Reference implementation:** the router returns these denials instead of
raising (`NoHealthyHostError` / `UnknownCapabilityError` stay exported for
compatibility but no longer escape `ainvoke` — a behavior change for callers
that caught them; the denial result is the protocol-correct shape). The
gateway CLI wires the evidence store its config already reserves. Prometheus
gains routing counters (failovers, unreachable denials, unhealthy-host gauge).

## Compatibility

Fully additive: no signed-object or canonicalization change — **every
published vector stays byte-identical**. A host that never routes never emits
any of this and remains conformant. The wire conformance suite stays at 18: a
black-box single-host runner cannot exercise a mesh; coverage is alignment
guards (denial-code registries, reserved-names, a new `spec_defines_routing`
check) + reference router unit tests + the live mesh proof. TS parity: none —
no TS router exists, and `ts-types`' evidence list is a legacy pre-registry
surface not synced to reserved-names (syncing it wholesale is a separate,
named cleanup; adding two strings to a stale list would fake parity).

Deferred by design: an active health prober (reactive marking suffices until a
consumer needs faster detection), client-side backoff in
`RemoteCapabilityHost`, persistence of the unhealthy set across gateway
restarts, a gateway wire-conformance fixture (spawn-mesh harness), jobs-adapter
retry/dead-letter, and any load-shedding vocabulary.

## Shipped as

- Spec: chp-v0.2.md **§11 Routing & Reachability**; binding §3 routing-
  intermediary paragraph; governance §2 row + retryable rule rewritten
  ("governance OR reachability"); pipeline §2 "before the pipeline" note;
  CHANGELOG **[0.2.4]**
- Guards: `spec_defines_routing` (alignment, 58 checks); the four denial-code
  registry guards; `reserved_names_registry_current` (20 families, 11 codes);
  wire suite unchanged at 18 (gateway fixture = named deferral, as proposed)
- Implementations: `MultiHostRouter` returns processed denials (raises
  retired), optional `.store` with `_deny`-shaped `execution_denied` +
  transition-gated health events riding the routed correlation, replay merge
  of the gateway chain; gateway CLI store wiring (manifest `gateway.store` or
  `~/.chp/gateway-mesh.sqlite`); `chp_router_*` Prometheus metrics; `/verify`
  gateway-ness now detected by `export_task_bundle`, never absence-of-store
- Proven live: kill-member failover (`host_marked_unhealthy` under the
  invocation correlation) → HTTP 200 `host_unreachable`
  (attempted_hosts/retry_after_s) → recovery (`host_marked_healthy`) →
  stitched replay shows the whole story; metrics moved (failovers 2,
  unreachable 1, gauge 1→0)
- Refinement vs proposal: none — landed as designed
