# 0009: Sub-delegation — Attenuation-Only Mandate Chains

- **Status:** shipped (2026-07-11, spec v0.2.8)
- **Issue:** rad:0d03373
- **Affects:** chp-v0.2.md §10 (new "Sub-delegation" subsection + Forwarding update), `mandate` schema (three optional additive fields); canonical bytes: **no changes to existing objects** (the new header fields are omitted when absent — a single-hop mandate is byte-identical to v0.2.3; no new statement kind, denial code, or evidence type)

## Problem

Authority is single-hop. A mandate (§10) grants a delegate bounded rights,
but that delegate cannot re-delegate a *narrowed* slice to a sub-agent —
§10 twice defers sub-delegation as out of scope. Real agent meshes are
delegation trees: an orchestrator holds broad authority, hands a worker a
narrower slice, the worker hands a tool-runner narrower still. Today each
level needs its own out-of-band mandate from the root principal, who must
know every leaf in advance — which defeats the point of delegation.

## Design

A **sub-mandate** is a mandate that attenuates a parent mandate. The whole
design is one invariant — **attenuation is monotone: a child can only NARROW
scope and SHORTEN the validity window, never widen or extend** — plus
offline link-by-link verification back to the root principal.

A sub-mandate adds three fields to the mandate object:

```json
{
  "kind": "mandate", "mandate_id": "mnd_child", "depth": 1,
  "parent_id": "mnd_root",
  "delegate_id": "tool-runner", "scope": ["demo.echo"],
  "valid_from": "…", "valid_until": "…", "created_at": "…",
  "canonicalization": "chp-stable-v1",
  "principal": { "host_id": "worker", "public_key": "…", "host_identity": {…} },
  "parent": { …the full parent mandate, recursively… },
  "signature": { … }
}
```

- **`parent_id`** and **`depth`** are in the **signed header**
  (`kind, mandate_id, delegate_id, scope, valid_from, valid_until,
  created_at, depth, parent_id, canonicalization` — the last two present
  only when `parent_id` is set, so a root's header is byte-identical to a
  v0.2.3 mandate). `depth` is 0 at the root (field omitted), incremented per
  link.
- **`parent`** is the full parent mandate embedded inline (recursive) —
  **not** in the signed header. Its integrity is its own signature; the
  child commits to *which* parent via the signed `parent_id`, and the
  **delegate join** binds them: the parent's `delegate_id` MUST equal the
  child's `principal.host_id` (the parent delegated *to* this sub-principal).
  This is the statement-family precedent: reference by id in the header,
  carry the referenced object alongside, verify it on its own merits.
- **The sub-principal is the parent's delegate.** The worker that holds
  `mnd_root` (as `delegate_id`) signs `mnd_child` with the worker's own key —
  the delegate becomes a sub-principal. No key sharing, no root involvement.

**Verification** extends `verify_mandate` with a recursive branch. When a
`parent` is present, in addition to the normal leaf checks a verifier MUST
check, for the leaf-vs-parent link: `depth == parent.depth + 1` and
`depth ≤` an implementation cap; `parent_id == parent.mandate_id`; the
delegate join; `scope ⊆ parent.scope` (every child scope entry matches the
parent scope under the §2 grammar); and `[valid_from, valid_until] ⊆`
parent's window. Then it recurses into `parent` (carrying host time and the
revocation set, but not the leaf's delegate/capability bindings), until the
root (no `parent`) — the ordinary single-hop verification. Every hop uses
the key in its *own* `principal.host_identity`, so the entire chain verifies
**offline, with no prior relationship and no network** — the same trust
model as single-hop, made inductive.

- **Gate 5** is unchanged in shape: it already calls `verify_mandate` with
  the caller as `delegate_id` and the host's revocation set. The leaf's
  delegate binds to the transport-verified caller; ancestors bind via the
  join; the scope gate on the leaf remains correct because leaf ⊆ every
  ancestor by induction. The evidence subject additionally records the
  **root principal**, so the signed chain shows both who acted and whose
  ultimate authority it flowed from.
- **Revocation composes for free** (§10 Revocation, proposal 0007): the
  recursion runs each link's `not_revoked` check against *that link's* own
  principal key. Revoking any ancestor fails its `not_revoked`, which fails
  the whole leaf chain — **revoking a link kills the entire suffix** with no
  new mechanism.
- **A bad chain is `mandate_invalid`** — an attenuation violation, a broken
  join, an over-depth chain, or a revoked ancestor all fail gate 5 with the
  existing code. No new denial code.

**Forwarding interaction.** §10 Forwarding said an intermediary forwards a
mandate *unchanged*. Sub-delegation adds an option: an intermediary MAY
instead re-issue an **attenuated** sub-mandate (embedding the received one
as `parent`) before forwarding — narrowing authority as work fans out. The
executing host walks the chain either way; forwarding-unchanged remains
valid and is still the floor.

## Compatibility

Fully additive. A single-hop mandate has no `parent_id`/`depth`/`parent` and
is byte-identical to v0.2.3 — the existing `mandate.json` and
`mandate-revocation.json` vectors regenerate unchanged. A host that does not
implement chains simply never sees a `parent` (a chain presented to it fails
`verify_mandate`'s structure expectations and is denied — safe default). No
new statement kind, denial code, evidence type, or canonical-byte change to
any existing object. Wire conformance grows 22→23.

Deferred by design: cross-mesh chain pinning (requiring a specific root key
mesh-wide), the delegation-lifecycle promotion (`delegation_*` events),
`max_invocations` (unchanged from 0002), and a normative maximum depth (the
reference caps at 8; the spec leaves the ceiling implementation-defined).

## Shipped as

- Spec: chp-v0.2.md **§10 "Sub-delegation"** + Forwarding update + header-list
  note; CHANGELOG **[0.2.8]**; `mandate.schema.json` gains three optional
  additive fields (`parent_id`, `depth`, recursive `parent`)
- Bytes: existing `mandate.json` + `mandate-revocation.json` byte-identical
  (roots omit the new header fields); new `mandate-chain.json`; no new
  statement kind, denial code, or evidence type
- Guards: `spec_defines_subdelegation` + `sub_mandate_vector_verifies`
  (alignment 64→66); wire suite **22→23** (`check_sub_delegation`: valid
  chain → success with root_principal; widened scope / lengthened window →
  `mandate_invalid`; revoke-root → `mandate_invalid`; both reference hosts
  23/23)
- Implementations: Python `build_sub_mandate` / `_attenuates` /
  `mandate_header` conditional projection / `verify_mandate` recursion /
  `mandate_root_principal` + gate-5 root binding + `chp mandate delegate`;
  TS `buildSubMandate` / `attenuates` / `mandateRootPrincipal` /
  `verifyMandate` recursion (cross-verified against the Python-signed
  vector); `verify.mjs` recursive branch
- Refinement vs proposal: none — landed as designed; deferrals stayed named
  (cross-mesh chain pinning, delegation-lifecycle promotion, `max_invocations`,
  normative depth cap)
