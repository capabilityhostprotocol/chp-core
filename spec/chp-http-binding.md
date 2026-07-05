# Capability Host Protocol — HTTP Binding (v0.1)

Status: draft. Normative binding of the CHP object model
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

If no keys are configured the host MAY accept all callers (local-first default).
Network-layer confidentiality (e.g. a private mesh) MAY substitute for TLS.

## 3. Routes

`/` and `/health` are **public** (unauthenticated) for mesh probes and load
balancers; every other route requires auth (§2).

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/health` (= `/`) | public | — | `{status:"ok", host_id, protocol:"chp", version, host_version}` |
| GET | `/host` | required | — | `HostDescriptor` (+ `host_version`, and `assurance`/`key_id`/`public_key` when signed) |
| GET | `/capabilities` | required | — | `{capabilities: CapabilityDescriptor[]}` |
| POST | `/invoke` | required | `InvocationEnvelope` | `InvocationResult` (see §1) |
| GET | `/replay/{correlation_id}` | required | — | `ReplayResult` |
| POST | `/replay` | required | `ReplayQuery` | `ReplayResult` |
| GET | `/verify/{correlation_id}` | required | — | chain-verification result (§4) |
| GET | `/metrics` | required | — | Prometheus text (`text/plain; version=0.0.4`) |

`/invoke` accepts a convenience form: a top-level `correlation_id` is lifted into
`correlation.correlation_id`. Responses are JSON with sorted keys.

`/health` MUST NOT disclose the live capability count (it stays on the authed
`/host` descriptor) — mesh-count privacy. `version` here is the protocol version;
`host_version` is the implementation version.

A host MAY add non-normative routes (the reference host exposes an OpenAI-
compatible `/v1/chat/completions` inference shim); a conforming client MUST NOT
depend on them.

## 4. Verification route

`GET /verify/{correlation_id}` returns the host's own chain check for that
correlation — at minimum `{valid: boolean}`, plus `first_broken_sequence` and the
counts the store's `verify_chain` produces. A gateway that holds no local store
(evidence distributed across a mesh) MUST instead return a JSON object with a
`note` explaining verification isn't available in gateway mode and the `hosts`
that hold the evidence — never a false `valid`. Offline bundle verification
(signatures, cross-language) is separate and lives in chp-v0.2.md §3.

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
