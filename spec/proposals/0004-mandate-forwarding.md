# 0004: Mandate Passthrough — Authority Transits Intermediaries

- **Status:** shipped (2026-07-10, spec v0.2.4)
- **Issue:** rad:d64fffb
- **Affects:** chp-v0.2.md §10 (new "Forwarding" subsection), chp-http-binding.md §2 (cross-reference sentence); canonical bytes: **no changes** (the envelope `mandate` field already exists, §10/v0.2.3)

## Problem

Mandates (§10) made authority a verifiable object presented in the invocation
envelope — but the reference routing intermediary drops it. A gateway
forwarding an invocation rebuilds the envelope without `mandate` and
authenticates to the member with its own per-peer key, so the executing host
sees `subject={"id":"router","type":"system"}`: the caller's identity AND
authority are both lost at the hop. A mandate presented at the front door
never reaches the host whose gate would verify it. The result is that every
routed invocation in the mesh runs on the gateway's ambient authority — the
exact pattern §10 was built to replace.

Subject loss at hops is **by design** (each host rebinds the subject to its
own verified transport caller — accountability, not assertion). Authority loss
is the bug: the mandate is precisely the object built to survive hops.

## Design

One normative rule (§10 "Forwarding"):

> An intermediary that forwards an invocation MUST forward a presented
> `mandate` **unchanged** on the forwarded envelope.

That is the whole mechanism. The intermediary does not verify the mandate (it
may not know the invoked capability's final resolution); the **executing
host's** gate 5 verifies it offline and rebinds the evidence subject to the
delegate-under-principal binding. Transport subject rebinding at each hop is
expected and unchanged — the mandate is the identity/authority carrier that
survives, cryptographically, end to end: the front-door caller's authority
lands verified in the executing host's signed chain no matter how many hops
sit between.

Delegate binding composes: on the final hop the transport-verified caller is
the *intermediary*, not the delegate — so an intermediary-forwarded mandate is
delegate-checked against the original caller only where transport auth
verified that caller (the front door). The executing host still enforces
signature, principal attestation, validity window, and scope in full.

**Reference implementation:** `MultiHostRouter.ainvoke` gains a `mandate`
parameter; `ainvoke_envelope` threads `envelope.mandate` through; the rebuilt
forwarded envelope carries it.

**Dogfood (the demand this answers):** the steward fleet mints one mandate per
steward per run — principal = the edge host key, delegate = `steward-<name>`,
scope = that steward's capability set, TTL sized to the run cadence — and
presents it on every invocation. Per-steward attribution then lands in every
member host's signed chain with zero new event types, replacing "the shared
gateway key did something" with "steward-emission acted under the edge host's
mandate, verifiably".

## Compatibility

Fully additive; no byte changes; every published vector byte-identical. An
intermediary that ignores the rule simply keeps today's behavior (the mandate
dies at the hop and routed invocations carry the intermediary's subject) —
callers relying on end-to-end mandate attribution need conforming
intermediaries, which the reference now is. Wire suite unchanged (the gate-5
check already covers host-side verification; the forwarding rule is exercised
by router unit tests + the live steward proof).

Deferred by design: mandate re-issuance/attenuation at intermediaries
(sub-delegation — a gateway narrowing a mandate before forwarding), delegate
binding through multi-hop transport-auth chains, and long-lived-process TTL
refresh (matrix-bot) — all wait for demand shaped by the steward dogfood.

## Shipped as

- Spec: chp-v0.2.md **§10 "Forwarding"** subsection; binding §2 cross-ref +
  §3 forwarding sentence; CHANGELOG **[0.2.4]**
- Guards: none new (host-side gate 5 already wire-checked at 18/18; the
  forwarding rule is covered by router unit tests, as proposed)
- Implementations: `MultiHostRouter.ainvoke(mandate=)` +
  `envelope.mandate` threaded through `ainvoke_envelope` into the rebuilt
  forwarded envelope (the drop point); 3 router tests (local path, envelope
  path, out-of-scope denied at the member)
- Dogfood: steward fleet mints one mandate per steward per run (principal =
  host key, delegate = steward-<name>, per-steward scope, TTL 7h); proven on
  the live mesh — every evidence event carries the delegate-under-principal
  subject; an expired mandate refused as `mandate_invalid` (temporal)
- Refinement vs proposal: none — landed as designed
