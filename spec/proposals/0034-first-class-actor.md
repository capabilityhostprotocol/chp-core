# 0034: First-class Actor Identity

- **Status:** shipped (spec v0.8.7, chp-core 0.44.0, npm alpha.38)
- **Issue:** rad:7bf202b2
- **Affects:** chp-v0.2.md §17 (new) + chp-application-contract.md §3.1 + a new
  `schemas/actor.schema.json` the invocation envelope `$ref`s. **No new reserved code**
  (a per-actor allowlist denial reuses `policy_blocked`). **Additive:** an envelope with
  no `actor` is byte-identical to a pre-0034 envelope. Spec **v0.8.6 → v0.8.7**. First
  additive change under the frozen Minimum CHP Application Contract (M1 of the portfolio
  substrate mandate).

## Problem

An invocation's identity is a free-form `subject` dict *derived entirely from host
credentials* — there is no first-class actor object, so a caller cannot carry a
structured, richer identity (type, owner, organization, trust, held authority), and
per-actor policy is impossible. `PolicyDescriptor.allowed_actors` has existed as a
declared field since early on but is **never read** — dead code. Both internal dogfood
applications need real actors: the Internal Chief of Staff (humans + agents as actors)
and CHP Home (the registered agent). This is substrate gap GAP 1.

## Design

**First-class actor (additive envelope object).** A new OPTIONAL `actor` on the
invocation envelope — a structured, caller-asserted identity:
`{ id, type, owner?, organization?, trust_level?, status?, credentials_ref?,
authority_refs? }`, with `type` ∈ {human, agent, service, workflow, device,
organization}. New `schemas/actor.schema.json`; the envelope adds an `actor` `$ref`
(not `required`), mirroring the `mandate` field exactly. Every field but `id` is
**omit-when-empty**; the envelope `to_dict` deletes `actor` when absent and the TS
client only adds it when present — so an envelope without an `actor` canonicalizes to
the exact pre-0034 bytes (canon iterates keys generically; an absent key contributes
zero bytes). Validated at the trust boundary (`Actor.from_mapping` → clean `ValueError`
→ HTTP 400, never a 500).

**Subject vs actor (both kept).** The `subject` stays the host's **verified
accountability record** — who authenticated, bound by the host, not by assertion. The
`actor` *enriches* it. The executing host records `actor` in evidence alongside
`subject` (omit-when-None, so pre-0034 events are byte-identical). The `actor` transits
the routing mesh **unchanged**, exactly like the mandate — the executing host records
and enforces it.

**Per-actor allowlist (wire the dead field).** `descriptor.policy.allowed_actors` is now
enforced at the governance gate, *after* the mandate gate finalizes the subject. The
**effective actor** = the verified `subject.id` when the subject is verified
(**accountability wins** — an asserted `actor` cannot override a host-verified caller),
else the asserted `actor.id`, else `subject.id`. A non-empty `allowed_actors` that
excludes the effective actor denies **`policy_blocked`** (no new reserved code); an
empty/absent list is open (today's behavior).

## Compatibility

Additive and byte-identical when unused. No wire break: the object model is frozen
additive-only; `actor` is a new optional field + a new schema. Three implementations
(Python core, TS host, stdlib `verify.mjs`) agree via `spec/test-vectors/actor.json`.
Authorized *discovery* (catalog-filtering by actor) and a distinct `actor_unauthorized`
denial code are deliberately **out of scope** — a later proposal (GAP 2, M2).

## Shipped as

- **Spec:** chp-v0.2.md §17; chp-application-contract.md §3.1 graduated to `spec/`.
- **Schema:** `schemas/actor.schema.json`; envelope `actor` `$ref`.
- **Vectors:** `spec/test-vectors/actor.json` (6 allowlist-decision KAT cases).
- **Guards:** `spec_defines_actor` + `actor_vector_verifies` (protocol_checks); the `$id`
  glob guard auto-registers the new schema.
- **Implementations:** Python (`types.Actor`, envelope + evidence field, host gate,
  `ainvoke` kwarg), TS (`ts-types` `Actor` + envelope field, `chp-sdk` client, `chp-host-ts`
  gate + evidence), `verify.mjs` matcher. Tests: `test_actor.py`.
