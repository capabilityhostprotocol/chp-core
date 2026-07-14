# Minimum CHP Application Contract

Status: **candidate** (v0.8.7, 2026-07-14). The stable surface every CHP application
relies on from the substrate — identity, discovery, invocation, governance, and
evidence — indexed over the normative objects in [chp-v0.2.md](chp-v0.2.md). This
contract is **additive-only** over the frozen object model; new optional fields and new
enum members only, never a removed or repurposed field. Additions are labelled
`implemented` / `planned`.

## 1. Vocabulary

- **Host** — a node in the capability mesh: a runtime that exposes and executes
  capabilities *and may route/federate to peers*. Not merely a process. (For the
  ownership boundary, say **provider / organization**.)
- **Capability** — a governed, typed, versioned ability; carries risk, side-effects,
  invariants, authority/policy references, and evidence behavior.
- **Actor** — a human, agent, service, workflow, device, or organization that requests,
  provides, approves, or observes capability use.
- **Mandate** — a signed, expiring, scoped, attenuating, revocable grant of authority.
- **Witness** — a peer that countersigns a host's store head (k-of-n quorum resists
  collusion).
- **Capability graph / mesh** — the union of hosts + the capabilities they serve + the
  edges between them (serves-capability, routes-to, witnesses, causal-parent).

## 2. Frozen objects (`implemented`)

Applications use these unforked. Each is normative in chp-v0.2.md / the schemas:

| Object | Surface |
|---|---|
| **Host identity** | host_id, public_key, key_id, valid_from/until, anchors (did/domain/rekor), signature, key_history |
| **Capability descriptor** | id, version, capability_uri, input/output schemas, `status` (lifecycle), modes, idempotency, side_effects, invariants, risk, `policy`, autonomy, depends_on, host_requirements |
| **Invocation envelope** | capability_id, version, requested_capability_version, payload, subject, mandate, actor, correlation, invocation_id |
| **Discovery** | attribute filter + version negotiation (`supported_versions` / `negotiate_version`) |
| **Mandate** | principal, delegate, scope, valid_from/until, max_invocations, attenuation chain, revocation |
| **Normalized errors** | the reserved denial codes; vendor codes reverse-DNS namespaced |
| **Evidence / provenance** | append-only SHA256 chain, `verify_chain`, DSSE/in-toto, Rekor anchors, selective disclosure |
| **Pipeline** | the ordered governance gates, first-fail-wins |
| **Mesh & federation** | capability-addressed routing, exactly-once gateway, `chp-causal-order-v1` task bundles, federated verify (causal-closure) |

## 3. Additive surface

### 3.1 First-class Actor — `implemented` (chp-v0.2.md §17, proposal 0034)
An optional `actor` object on the envelope (`id` + `type` + `owner` / `organization` /
`trust_level` / `status` / `credentials_ref` / `authority_refs`) — a structured,
caller-asserted identity. The verified `subject` stays the accountability record;
`actor` enriches it and drives the per-actor allowlist (`descriptor.policy.allowed_actors`
→ `policy_blocked`). Omit-when-absent → byte-identical to a pre-0034 envelope.

### 3.2 Further additive surface — `planned`
Additional optional envelope references (idempotency key, approval reference, provenance
reference, structured policy context), a richer policy decision enum with versioned
decision records, a durable approval queue with resumable invocation, and a typed node /
materialized capability-graph model are **planned additive extensions**, each gated by
the protocol-change discipline (implementation pressure + generality + compatibility +
conformance test) and tracked in [proposals/](proposals/). None is on the wire yet; no
application should assume them.

## 4. The five guarantees

Every application relies on exactly these, from the substrate, unforked:
**Identity** (stable host/capability/actor ids + provider + trust context) · **Discovery**
(typed, version/lifecycle-filtered, health-annotated; discover ≠ invoke) · **Invocation**
(actor + capability@version + typed input + mandate + correlation/causation + idempotency
→ normalized result or reserved-code denial) · **Governance** (mandate scope + policy
decision + explanation + approval state + immutable decision record) · **Evidence**
(append-only audit + trace + input/output hashes + versions + parent invocation;
verifiable across hosts).

## 5. Freeze semantics

Versioned; additive-only (new optional fields / new enum members); omit-when-absent
preserved so unused additions never change canonical bytes; each addition ships with a
vector + an alignment guard + 3-implementation agreement.
