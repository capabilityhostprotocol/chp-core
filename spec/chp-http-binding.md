# Capability Host Protocol — HTTP Binding (v0.2)

Status: **released** (v0.2 2026-07-06; v0.2.1–v0.2.3 additions 2026-07-09). Changes via [proposals/](proposals/) — see [CHANGELOG.md](CHANGELOG.md). Normative binding of the CHP object model
([v0.1](chp-v0.1.md)) onto HTTP, so a host in any language is wire-compatible
with the reference `RemoteCapabilityHost` client and the black-box conformance
runner (`conformance/runner.py --url`). CHP is transport-agnostic; this is the
one binding v0.2 specifies normatively.

Key words MUST, SHOULD, MAY per RFC 2119.

## 1. The load-bearing rule: process vs transport

**A CHP outcome is not an HTTP status.** If the host *processed* an invocation —
including deciding to deny, fail, or skip it — the HTTP response is **`200 OK`**
and the CHP `outcome` lives in the JSON body. A non-2xx status means the request
never became a governed invocation (bad JSON, unknown route, unauthenticated).

| Situation | HTTP status | Body |
|---|---|---|
| Invocation processed — `success`, `failure`, `denied`, or `skipped` | `200` | `InvocationResult` (`outcome` field carries the verdict) |
| Malformed / missing field | `400` | error envelope |
| Missing or invalid `X-CHP-Key` | `401` | error envelope |
| Unknown route | `404` | error envelope |

This is deliberate: a `denied` invocation is a **successful governance
decision**, not a transport failure — it produces evidence and MUST be returned
as `200` so the caller reads `outcome: "denied"` and its `DenialReason`
(chp-governance-v0.2.md §2), never a bare `403`. A client that treats HTTP status
as the outcome is non-conforming.

The error envelope is `{"error": {"code": string, "message": string}}`.

## 2. Authentication

Authenticated routes require an **`X-CHP-Key`** request header. The host compares
credentials in **constant time** (MUST — no early-exit string compare). Two
configurations:

- **Shared key** — a single key accepted from any caller.
- **Named per-caller keys** — `name:key` pairs. On a match, the host binds the
  caller `name` as the **verified `subject`** on the resulting evidence,
  overriding any `subject` in the request body (chp-v0.2.md §5 — a MUST for the
  governed/signed tiers). This is what makes "agent X did Y" *provable* rather
  than *asserted*.

**Key rotation (overlap window).** The same caller name MAY appear with
several keys simultaneously (`agent-a:new,agent-a:old`) — all entries
authenticate as the same verified subject. Rotation is therefore add-new →
drain → remove-old, with no authentication gap and no distinct rotation
protocol. Every configured entry is compared in constant time.

**Capability-scoped keys.** A named key MAY carry a capability scope —
`name:key:scope1|scope2`, where each scope is an exact capability id or a
trailing-`*` prefix (`chp.adapters.audit.*`). An invocation outside the key's
scope is a **processed governance denial**: outcome `denied` with the reserved
`policy_blocked` code, returned as HTTP `200` **with evidence emitted** (§1 —
a scope decision is governance, never a bare transport 403). An unscoped key
is unrestricted (today's behavior). Scope is enforced by the host that
authenticates the caller.

**Mandates (delegated authority).** Beyond keys, an invocation MAY present a
signed **mandate** in the envelope (chp-v0.2.md §10) — a principal's expiring,
capability-scoped grant naming the caller as delegate. The mandate does not
authenticate the connection (a key, or the open local-first default, still
does that); it *narrows and attributes*: when transport auth has verified a
caller, the mandate MUST name that caller as `delegate_id`, and on success the
evidence subject becomes the delegate-under-principal binding. Mandate scope
uses this section's grammar; verification failures are processed
`mandate_invalid` denials and out-of-scope invocations are `policy_blocked` —
HTTP 200 with evidence, per §1.

If no keys are configured the host MAY accept all callers (local-first default).
Network-layer confidentiality (e.g. a private mesh) MAY substitute for TLS.

## 3. Routes

`/` and `/health` are **public** (unauthenticated) for mesh probes and load
balancers; every other route requires auth (§2).

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/health` (= `/`) | public | — | `{status:"ok", host_id, protocol:"chp", version, host_version}` |
| GET | `/.well-known/chp-identity` | public | — | identity document `{assurance, key_id?, public_key?, host_identity?, key_history?, revoked_keys?}` (chp-v0.2.md §3.1–3.2) |
| GET | `/host` | required | — | `HostDescriptor` (+ `host_version`, and `assurance`/`key_id`/`public_key` when signed) |
| GET | `/capabilities` | required | — | `{capabilities: CapabilityDescriptor[]}` |
| POST | `/invoke` | required | `InvocationEnvelope` | `InvocationResult` (see §1) |
| GET | `/replay/{correlation_id}` | required | — | `ReplayResult` |
| POST | `/replay` | required | `ReplayQuery` | `ReplayResult` |
| GET | `/verify/{correlation_id}` | required | — | chain-verification result (§4) |
| GET | `/export/{correlation_id}` | required | — | this host's (signed when keyed) evidence bundle; on a gateway, the assembled cross-host **task bundle** (§4a) |
| GET | `/metrics` | required | — | Prometheus text (`text/plain; version=0.0.4`); MAY include integrity counters (`chp_verify_requests_total{valid}`, `chp_chain_breaks_total`) so verification failures are alertable, not only evidence |

`/invoke` accepts a convenience form: a top-level `correlation_id` is lifted into
`correlation.correlation_id`. Responses are JSON with sorted keys.

`/health` MUST NOT disclose the live capability count (it stays on the authed
`/host` descriptor) — mesh-count privacy. `version` here is the protocol version;
`host_version` is the implementation version.

`/.well-known/chp-identity` is public by design: a never-met verifier must be
able to resolve the host's key without credentials (its authority comes from
the TLS origin serving it — chp-v0.2.md §3.1). It serves key/identity material
only; capability data stays behind auth.

A host MAY add non-normative routes (the reference host exposes an OpenAI-
compatible `/v1/chat/completions` inference shim); a conforming client MUST NOT
depend on them.

## 4. Verification route

`GET /verify/{correlation_id}` returns the host's own chain check for that
correlation — at minimum `{valid: boolean}`, plus `first_broken_sequence` and the
counts the store's `verify_chain` produces.

A gateway that holds no local store SHOULD perform **federated verification**
(chp-v0.2.md §8): assemble the task bundle from each member host's `/export`
and return the task-bundle verification result with `"mode": "federated"`
(`valid` is present and honest). A gateway that cannot (members lack `/export`,
or a member is unreachable) MUST return either a `503` naming the unreachable
hosts or the legacy JSON `note` object ("verification isn't available…", plus
the `hosts` that hold the evidence) — **never a false `valid`**, and never a
silently-partial result. Offline bundle verification (signatures,
cross-language) is separate and lives in chp-v0.2.md §3/§8.

### 4a. Export route

`GET /export/{correlation_id}` on a **single host** returns that host's evidence
bundle for the correlation, signed when the host holds a key (chp-v0.2.md §3).
On a **gateway**, it returns the assembled cross-host **task bundle**
(chp-v0.2.md §8): the gateway fans out to every member's `/export`, keeps
members with ≥1 event, sorts canonically, and aggregates — at request time,
never storing evidence. If any member is unreachable the gateway MUST respond
`503` listing the unreachable hosts: a silently-partial evidence bundle is the
failure mode task bundles exist to prevent; the caller retries.

### 4b. Federated replay is never silently partial

A gateway `/replay` fans out to member hosts and merges the timeline
(chp-causal-order-v1). Unlike `/export`, replay is a *read view*, so a partial
result is permitted — but it MUST be disclosed: when any member could not
contribute, the `ReplayResult` MUST carry `partial: true` and name the
unreachable members in `missing_hosts`. A merged timeline that silently omits
a member's events misrepresents the causal record; a consumer that requires
completeness uses `/export` (which refuses partiality outright).

## 5. Conformance

The black-box runner (`conformance/runner.py --url <base>`) drives a running host
over this binding through the reference `RemoteCapabilityHost` client and checks
the class-A normative behaviours: discovery (`/host`, `/capabilities`), an
`InvocationEnvelope` round-trip, correlation propagation, the §1 status rule
(a denied invocation returns `200` with `outcome:"denied"`), replay by
correlation id, and — when the host declares a signed tier — `/verify`.

A host-under-test SHOULD pre-register the **conformance fixture profile** so the
runner has known capabilities to exercise: `conformance.echo` (returns its
payload — `success`), `conformance.fail` (always `failure`), `conformance.guarded`
(`denied` with a reserved `DenialReason`), `conformance.approval` (autonomy tier
`approval_required` — exercises the approval-gate governance path),
`conformance.budgeted` (autonomy `action_limit=1` — exercises the budget path),
`conformance.risky` (risk tier above the host's cap — exercises risk-tier
enforcement), and `conformance.unsafe` (blocked by a safety guardrail —
exercises the safety path). The runner reports which normative checks the wire
host passed.
