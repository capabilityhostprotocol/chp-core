# Capability Host Protocol — Zenoh Binding (v0.2)

Status: **released** (v0.8.2 2026-07-13, [proposal 0032](proposals/0032-zenoh-binding.md)).
A normative binding of the CHP object model ([v0.1](chp-v0.1.md)) onto a
[Zenoh](https://zenoh.io) query/reply + pub/sub data plane — the sibling of the
[HTTP binding](chp-http-binding.md). CHP is transport-agnostic; this is the second
binding it specifies normatively.

The **wire objects are unchanged**: an invocation carries the exact
`InvocationEnvelope` JSON the HTTP binding's `POST /invoke` body carries, and a reply
carries the exact `InvocationResult` JSON. **Only the carrier differs** — a Zenoh
`get()` against a queryable instead of an HTTP request. A host reachable over Zenoh is
therefore wire-compatible with one reached over HTTP; the reference is
`chp-transport-zenoh` (`ZenohTransport` + `ZenohHostServer`), and it satisfies the same
`chp_core.transport.Transport` protocol as `HttpTransport`, so the router composes the
two with no change.

Key words MUST, SHOULD, MAY per RFC 2119.

## 1. Why a second binding

HTTP is request/response over a point-to-point connection. A Zenoh data plane adds two
things HTTP cannot: **peer discovery + presence** (a host is found and watched via key
scouting and liveliness, no registry or fixed address) and **native evidence pub/sub**
(a host broadcasts evidence to any number of subscribers). The binding keeps CHP's
guarantees — the same signed envelope/result objects, the same governance pipeline —
while gaining a mesh-native carrier. This binding specifies the *transport*, not new
evidence semantics: everything under §12–§16 of [chp-v0.2.md](chp-v0.2.md) applies
unchanged to the objects it carries.

## 2. Key-expression table

All keys use the prefix `chp/v1` by default (configurable per host). `{host_id}` is the
serving host's id.

| Key expression | Zenoh primitive | Direction | Purpose |
|---|---|---|---|
| `chp/v1/invocations/{host_id}/requests` | Queryable | Caller → Host | **Invoke**: query payload = `InvocationEnvelope` JSON; reply = `InvocationResult` JSON |
| `chp/v1/capabilities/{host_id}/declarations` | Queryable | Querier → Host | **Discover**: reply = the host descriptor (`{id, capabilities, …}`) |
| `chp/v1/capabilities/*/declarations` | Get (wildcard) | Querier → Mesh | Discover **all** hosts' capabilities in one query |
| `chp/v1/replay/{host_id}/requests` | Queryable | Auditor → Host | **Replay**: query payload = `{correlation_id}`; reply = `{events:[…]}` |
| `chp/v1/health/{host_id}` | Queryable | Prober → Host | **Health**: reply = `{status, host_id, protocol, capability_count}` |
| `chp/v1/evidence/{host_id}/stream` | Put / Subscribe | Host → Mesh | **Evidence broadcast**: the host `put()`s each handled invocation's completed evidence; any subscriber receives it |

A host **MUST** answer the invoke, declarations, replay, and health queryables. It
**SHOULD** publish to the evidence stream (the mesh-native capability); a caller
**MAY** subscribe. Presence **MAY** be advertised with a Zenoh **liveliness token**
under `chp/v1/capabilities/{host_id}/liveliness`, so observers watch hosts join/leave
without polling.

## 3. Serialization

Every payload is **UTF-8 JSON** of the corresponding CHP object — identical bytes to
the HTTP binding (`InvocationEnvelope.to_dict()` / `InvocationResult.to_dict()`), so a
bundle produced over Zenoh verifies exactly as one produced over HTTP. The query on the
invoke key carries the envelope as its `payload`; the queryable replies on the same key
with the result. Replay and health queries with no request body carry an empty payload.

The invoke queryable runs the **full CHP pipeline** (chp-invocation-pipeline.md) on the
envelope exactly as the HTTP `/invoke` route does — a processed invocation
(success/failure/denied/skipped) is returned as an `InvocationResult` reply; the carrier
does not change any gate.

## 4. Evidence pub/sub

After a host processes an invocation it **SHOULD** `put()` that invocation's
`execution_completed` evidence event (the same event object recorded in its store) to
`chp/v1/evidence/{host_id}/stream`. Subscribers receive the raw evidence JSON; because
the event carries the chain fields (`content_hash`, `prev_hash`, `sequence`,
`payload_commitment`), a subscriber can verify it against the host's store head exactly
as a bundle consumer would. This is the binding's distinguishing feature: evidence is a
**stream**, not only a per-request response.

## 5. Auth / confidentiality

Zenoh's own transport security (TLS / mTLS / access control at the Zenoh layer) carries
the confidentiality and authentication MUSTs of [chp-v0.2.md §5](chp-v0.2.md) — the same
role TLS plays for the HTTP binding. Subject binding, mandates (§10), sealed payloads
(§16), and every other object-level guarantee are unchanged: they live in the JSON the
binding carries, not in the carrier.

## 6. Conformance

A Zenoh-binding host is conformant when, for the shipped envelope, its invoke reply is
byte-identical (modulo ids/timestamps) to the same envelope processed over the HTTP
binding or in-process; discover/replay/health answer their queryables; and the evidence
stream delivers the completed event. The reference profile round-trips an `math.add`
invocation between a `ZenohHostServer` and a `ZenohTransport` and asserts exactly this.
