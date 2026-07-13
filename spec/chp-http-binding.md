# Capability Host Protocol — HTTP Binding (v0.2)

Status: **released** (v0.2 2026-07-06; v0.2.1–v0.2.9 additions 2026-07-09/11). Changes via [proposals/](proposals/) — see [CHANGELOG.md](CHANGELOG.md). Normative binding of the CHP object model
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
HTTP 200 with evidence, per §1. A routing intermediary MUST forward a
presented mandate unchanged (chp-v0.2.md §10 Forwarding) — the mandate is the
authority carrier that survives per-hop subject rebinding.

If no keys are configured the host MAY accept all callers (local-first default).
Network-layer confidentiality (e.g. a private mesh) MAY substitute for TLS.

**Mutual TLS (proposal 0031).** A host MAY require a client certificate at the TLS
layer, verified against a configured CA (`CERT_REQUIRED` + a CA bundle). A verified
client cert authenticates the caller *before the pipeline* — an unknown-CA or absent
cert is refused during the handshake (a connection-level failure, no HTTP response,
no reserved code). The verified cert identity — subject commonName, else the first
DNS `subjectAltName` — becomes the verified `subject` (`{id, type: "mtls", verified:
true}`), overriding any client-asserted subject exactly like a key or token. mTLS is a
third credential alongside `X-CHP-Key` and `X-CHP-Token` and, being verified by the
transport itself, takes precedence when present. Certificate issuance/rotation and CA
operation are deployment concerns outside this binding.

**Version selection (`X-CHP-Version`).** A request MAY carry an optional
**`X-CHP-Version`** header naming the wire version the caller selected from the
host's `supported_versions` (chp-v0.2.md §1.1). When **absent**, the host
processes under its `protocol_version` — the default, so no caller is required to
send it. When **present and supported**, the host processes under that version.
When **present and NOT in `supported_versions`**, the host MUST reject the
request with HTTP `400` and a body `{error, denial:{code:"version_unsupported",
…}}` rather than silently processing under a version the caller did not ask for
(chp-v0.2.md §1.1 — the tier-rejection rule extended to the wire version). This
is a *transport-level* rejection before routing (like an auth failure), not a
processed governance denial, so it is `400`, not `200`-with-evidence.

## 3. Routes

`/` and `/health` are **public** (unauthenticated) for mesh probes and load
balancers; every other route requires auth (§2).

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/health` (= `/`) | public | — | `{status:"ok", host_id, protocol:"chp", version, host_version}` |
| GET | `/.well-known/chp-identity` | public | — | identity document `{assurance, key_id?, public_key?, host_identity?, key_history?, revoked_keys?}` (chp-v0.2.md §3.1–3.2) |
| GET | `/host` | required | — | `HostDescriptor` (+ `host_version`, `supported_versions` (§1.1), and `assurance`/`key_id`/`public_key` when signed) |
| GET | `/capabilities` | required | — | `{capabilities: CapabilityDescriptor[]}` |
| POST | `/invoke` | required | `InvocationEnvelope` | `InvocationResult` (see §1) |
| GET | `/replay/{correlation_id}` | required | — | `ReplayResult` |
| POST | `/replay` | required | `ReplayQuery` | `ReplayResult` |
| GET | `/verify/{correlation_id}` | required | — | chain-verification result (§4) |
| GET | `/export/{correlation_id}` | required | — | this host's (signed when keyed) evidence bundle; on a gateway, the assembled cross-host **task bundle** (§4a) |
| GET | `/metrics` | required | — | Prometheus text (`text/plain; version=0.0.4`); MAY include integrity counters (`chp_verify_requests_total{valid}`, `chp_chain_breaks_total`) so verification failures are alertable, not only evidence |
| GET | `/head` | required | — | the witnessable store head `{host_id, scheme, sequence, store_head, at}` (chp-v0.2.md §12; authed — the sequence discloses activity volume) |
| POST | `/witness` | required | `chain-witness` statement | `{accepted, sequence, witness}`; the host MUST verify the signature AND recompute its own head at that sequence before persisting (400 `invalid_witness` / 409 `head_mismatch`) |
| GET | `/witnesses` | required | — | `{witnesses: [chain-witness…]}` — received countersignatures over this host's history (statements only; leaf snapshots stay local) |
| GET | `/revocations` | required | — | `{keys: [key-revocation…], mandates: [mandate-revocation…]}` — the revocation set this host holds (chp-v0.2.md §10; keys per §3.2) |
| POST | `/revocations` | required | `mandate-revocation` statement | `{accepted, mandate_id, principal}`; the host MUST verify the statement (signature + attestation) before persisting (400 `invalid_revocation`) — never store an unverifiable revocation |

`/invoke` accepts a convenience form: a top-level `correlation_id` is lifted into
`correlation.correlation_id`. Responses are JSON with sorted keys.

**Routing intermediaries.** A gateway that routes `/invoke` to member hosts is
bound by §1 at its own layer: an invocation it PROCESSES — including deciding
that **no owner of the capability is reachable** — returns `200` with a denial,
never a bare 5xx. No reachable owner → the reserved `host_unreachable` code
(`retryable: true`; `details` SHOULD carry `attempted_hosts`, `last_error`,
`retry_after_s`); capability unknown mesh-wide → `capability_not_found`. The
intermediary MUST record such denials as evidence when it maintains an
evidence store, and SHOULD maintain one (chp-v0.2.md §11). A presented
`mandate` MUST be forwarded unchanged on the routed envelope (§2, chp-v0.2.md
§10 Forwarding).

**Streaming invocations** ([proposal 0006](proposals/0006-governed-streaming.md)).
`mode:"stream"` on `POST /invoke` responds with `text/event-stream`: zero or
more `event: chunk` frames (`data: {"delta": …}`) followed by exactly one
terminal `event: result` frame whose `data` is the standard
`InvocationResult`. The gate pipeline runs **before** the stream opens —
any outcome decided before the first chunk (a denial, a skip, a
non-streaming handler) is returned as the normal JSON `200` body, and the
response MUST NOT commit to `text/event-stream` in that case; clients switch
on Content-Type. Evidence brackets the stream: `execution_started` at open,
`execution_completed` (SHOULD carry usage: `prompt_tokens`,
`completion_tokens`, `model`) or `execution_failed` at close. A capability
advertises streaming via `modes: ["sync","stream"]`; `mode:"stream"` against
a sync-only capability is the ordinary gate-4 `unsupported_mode` denial.
SSE frames are transport, not canonical objects — nothing here is hashed or
signed. **Resumable streams** (v0.3.1, [proposal 0012](proposals/0012-streaming-completion.md),
chp-v0.2.md §13.1): each `event: chunk` frame carries an `id: <n>` line (n =
0-based chunk index) and the terminal `result` frame the final id; a client
whose connection drops reconnects to `POST /invoke` with the **same
`invocation_id`** and a `Last-Event-ID: <n>` header, and the host resumes the
stream from chunk **n+1** off its recorded buffer (then the terminal result).
Resume and streaming replay (a retried `invocation_id`) share one
replay-from-offset path; a host that does not implement resume answers the
reconnect as a fresh stream. Keep-alive ping frames remain unspecified.

**Idempotent replay** ([proposal 0008](proposals/0008-idempotent-replay.md),
chp-v0.2.md §13). The envelope's `invocation_id` is the idempotency key — no
header. A `POST /invoke` presenting an `invocation_id` the host has already
recorded returns the RECORDED result with `"replayed": true` (omitted on
fresh executions), same 200-with-outcome rule as everything else. A caller
that wants retry-safety reuses the id across attempts; a fresh id always
executes fresh. Window-bounded (host-configured retention); streaming mode
excluded.

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

**Routing intermediaries** have their own suite (`runner.py --gateway-url
<base> --suite mesh`): the runner hosts two reference member hosts, the
gateway-under-test routes between them, and the runner induces failure by
killing its own member — proving the §3 intermediary obligations black-box
(processed `host_unreachable`, mandate forwarding per chp-v0.2.md §10, merged
+ disclosed-partial `/replay`, 503-on-partial `/export`). The fixture profile
(topology, keyless members, evidence-store requirement, members-first start
order) is [conformance/MESH-FIXTURES.md](../conformance/MESH-FIXTURES.md).
