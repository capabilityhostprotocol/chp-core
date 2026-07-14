# 0032: Zenoh Transport Binding

- **Status:** shipped (spec v0.8.2, chp-transport-zenoh 0.39.0)
- **Issue:** rad:48f767ed
- **Affects:** a NEW normative binding doc `chp-zenoh-binding.md` (sibling of
  chp-http-binding.md) + a NEW downstream package `chp-transport-zenoh`. **No change to
  chp-core** — the wire objects, the pipeline, and the `Transport` protocol are all
  unchanged; `chp-core` stays `dependencies = []`. Spec **v0.8.1 → v0.8.2** (a new
  transport binding, additive).

## Problem

CHP is transport-agnostic but had only **one** normative binding (HTTP). HTTP is
request/response over a point-to-point connection: a host needs a known address, there
is no native presence, and evidence can only be pulled per-request. A mesh wants the
opposite — peers that **discover** each other, advertise **presence**, and **stream**
evidence to many subscribers. Zenoh (a query/reply + pub/sub data plane) provides
exactly that. The `Transport` protocol was designed for this from the start — its module
docstring names Zenoh as the intended downstream binding — but no such binding existed.

## Design

**A second binding, not a second protocol.** The invoke query payload IS the
`InvocationEnvelope` JSON the HTTP `POST /invoke` body carries; the reply IS the
`InvocationResult` JSON. Byte-identical objects, byte-identical verification — only the
carrier differs (a Zenoh `get()` against a queryable instead of an HTTP request). The
invoke queryable runs the **full CHP pipeline** unchanged; the carrier changes no gate.

**Key-expression table** (`chp/v1` prefix, per-host): a queryable each for **invoke**
(`…/invocations/{host_id}/requests`), **discover** (`…/capabilities/{host_id}/declarations`,
wildcard-discoverable across the mesh), **replay** (`…/replay/{host_id}/requests`), and
**health** (`…/health/{host_id}`); an **evidence** put/subscribe stream
(`…/evidence/{host_id}/stream`) the host broadcasts each handled invocation's completed
event to — the mesh-native capability HTTP lacks. Presence MAY use a Zenoh **liveliness
token**.

**Satisfies the `Transport` protocol.** `ZenohTransport` implements the same five
methods (`ainvoke_envelope`, `discover`, `replay_result`, `health`, `supports`) plus the
optional `subscribe_evidence`, each a Zenoh call run in a worker thread (mirroring how
`HttpTransport` wraps blocking `urllib`), so the **router composes it with zero
changes**. `ZenohHostServer` declares the queryables backed by a `LocalCapabilityHost`.

**Placement.** A downstream package `chp-transport-zenoh` carries the `eclipse-zenoh`
dependency; installing it is what pulls Zenoh in, so `chp-core` stays dependency-free.
`chp-host` gains a `zenoh://<host_id>` remote-URL scheme (lazy-imports the package only
when used).

**Auth/confidentiality** ride on Zenoh's own transport security (TLS/mTLS/ACL at the
Zenoh layer), satisfying §5's MUSTs exactly as TLS does for HTTP; every object-level
guarantee (subject binding, mandates, sealed payloads) is unchanged because it lives in
the carried JSON, not the carrier.

## Compatibility

Purely additive. No chp-core code, wire object, schema, or reserved code changes — a
host that speaks only HTTP is unaffected. The Zenoh binding is opt-in by installing a
separate package. A **minor** spec bump (v0.8.2) for the new normative binding doc.

## Deferred by design

**TS `ZenohTransport`** parity (the TS runtime already speaks Zenoh via
`@auxo/zenoh-core` — a follow-up); Zenoh **liveliness-based routing** beyond simple
presence; capability-scoped evidence keys (`…/evidence/{capability_id}/stream` — this
ships a per-host stream); a gateway/router that bridges HTTP ⇄ Zenoh hosts; streaming
*invocation* (chunked results over Zenoh — this ships terminal query/reply). **Rekor
submission** moves to proposal 0033.

## Shipped as

- **Spec v0.8.2** — `chp-zenoh-binding.md` (key table, serialization, evidence pub/sub,
  conformance).
- **chp-transport-zenoh 0.39.0** — `ZenohTransport` (Transport protocol) +
  `ZenohHostServer` (queryables) + `keys()`/`result_from_dict`; own `eclipse-zenoh>=1.0`
  dep. `chp-host` `zenoh://` scheme dispatch.
- **Tests + guard** — `test_zenoh_transport.py` (byte-identical round-trip vs in-process,
  discover/health/replay over Zenoh, evidence pub/sub delivers the completed event);
  guard `spec_defines_zenoh_binding`.
