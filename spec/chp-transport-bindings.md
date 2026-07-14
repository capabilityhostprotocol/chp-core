# Capability Host Protocol — Transport Bindings

Status: **overview** (non-normative). CHP is transport-agnostic: the object model
([chp-v0.1.md](chp-v0.1.md), [chp-v0.2.md](chp-v0.2.md)) — envelopes, results,
evidence, mandates, anchors — is defined independent of any wire. A **binding** maps
those objects onto a concrete carrier. This document indexes the bindings CHP specifies
normatively and states what any binding must preserve.

## The two normative bindings

| Binding | Carrier | Doc | Shape |
|---|---|---|---|
| **HTTP** | request/response over HTTP(S) | [chp-http-binding.md](chp-http-binding.md) | point-to-point; the reference client is `RemoteCapabilityHost`, the reference host is the stdlib `ThreadingHTTPServer` |
| **Zenoh** | query/reply + pub/sub | [chp-zenoh-binding.md](chp-zenoh-binding.md) | mesh-native: peer discovery, presence (liveliness), and an evidence broadcast stream; `ZenohTransport` / `ZenohHostServer` |

Both carry the **identical wire objects** — an invocation is the same
`InvocationEnvelope` JSON and a reply the same `InvocationResult` JSON in either
binding — so a bundle produced over one verifies exactly as one produced over the other,
and a host is wire-compatible across bindings. Both implementations satisfy the same
`chp_core.transport.Transport` protocol (five methods: `ainvoke_envelope`, `discover`,
`replay_result`, `health`, `supports`, plus an optional `subscribe_evidence`), so the
router composes them without change.

## What every binding MUST preserve

A conforming binding is a *carrier*, never a change to the guarantees:

1. **Object fidelity** — the envelope/result/evidence JSON is byte-identical to the
   canonical object model; canonicalization (`chp-stable-v1` / `chp-jcs-v1`) and the
   hash chain are unaffected by the carrier.
2. **The full pipeline** — a processed invocation runs every gate of
   [chp-invocation-pipeline.md](chp-invocation-pipeline.md); the carrier changes no gate
   and adds no denial. Process-vs-transport stays distinct: a *processed* invocation
   (success/failure/denied/skipped) is returned as a result; only a malformed request or
   a failed transport credential is a transport-level rejection.
3. **Confidentiality + auth (§5)** — the carrier MUST provide transport confidentiality
   (TLS/mTLS for HTTP; Zenoh's transport security for Zenoh, or an equivalent private
   fabric) and MUST bind an authenticated caller to a **verified** `subject`.
4. **Object-level guarantees are carrier-independent** — subject binding, mandates
   (§10), sealed payloads (§16), witnessed/anchored store heads (§12) all live in the
   carried JSON, so they hold identically over any binding.

## Adding a binding

A new binding (gRPC, MQTT, a message bus, …) implements the `Transport` protocol and a
host-side server for its carrier, serializes the same objects, runs the same pipeline,
and provides §5 confidentiality/auth. It ships as a **downstream package** so `chp-core`
stays dependency-free (the Zenoh binding is `chp-transport-zenoh`, carrying its own
`eclipse-zenoh` dependency). Document it as a sibling of the two binding docs above and
state its key/route table + serialization; the wire objects — and their verification —
do not change.

## Implementation status

- **HTTP** — Python (`chp_core.http`) + TypeScript (`@capabilityhostprotocol/host`),
  wire-conformant both ways.
- **Zenoh** — Python (`chp-transport-zenoh`); a TypeScript `ZenohTransport` is a planned
  follow-up (the TS runtime already speaks Zenoh over `@eclipse-zenoh/zenoh-ts`).
