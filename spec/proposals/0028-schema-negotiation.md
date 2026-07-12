# 0028: Cross-host Capability-Version Negotiation

- **Status:** shipped (spec v0.7.3, chp-core 0.36.0, npm alpha.27)
- **Issue:** rad:ad6bbe73
- **Affects:** chp-v0.2.md §1.1 (a capability-version axis beside wire-version
  negotiation) + chp-invocation-pipeline.md gate 2; a new
  **`capability_version_unsupported`** reserved code + an optional
  `requested_capability_version` envelope field. **Additive** — absent the field,
  resolution is unchanged. Spec **v0.7.2 → v0.7.3**.

## Problem

A `CapabilityDescriptor` carries `version` and `output_schema`, and the resolver
already matches an *exact* `(capability_id, version)`. But nothing negotiates
capability **compatibility**: a caller can only ask for one exact version or the
single registered match. Hosts negotiate the *wire* version (§1.1) but not the
*capability* version. In a mesh that evolves — a host upgrades `analyze@1.0` to
`analyze@2.0` — a client pinned to `1.x` has no way to say so, and an exact miss is
reported as `capability_not_found`, which is wrong (the capability *exists*).

## Design

**A requested range.** An invocation MAY carry `requested_capability_version` — a
semver **range**, a practical subset both reference implementations parse
identically:

- exact `1.0.0`; caret `^1.2.0` (`>=1.2.0 <2.0.0`); tilde `~1.2.3` (`>=1.2.3
  <1.3.0`); comparators `>= > <= < =`; x-ranges `1.x` / `1` / `1.2.x`; `*` (any);
  space = **AND** (`>=1.0 <2`).

**At the resolution gate (pipeline gate 2).** The host resolves `capability_id`.
When `requested_capability_version` is present it gathers the registered versions
of that id: if **none** are registered → `capability_not_found` (as today); if some
are registered but **none satisfies the range** → **`capability_version_unsupported`**
(`retryable: false`; `details` carry `requested` + the `available` versions); else
it resolves to the **highest** satisfying version. Absent the field, resolution is
unchanged (exact `version`, or the single registered match). The new code is
distinct from `capability_not_found` precisely because the capability exists — the
client learns *"I have this, just not the version you need,"* which is actionable.

**Why a clean denial (not router auto-select).** The baseline is single-host
correctness: a host answers honestly about what it offers and the caller decides.
Router auto-selection of a compatible variant across many hosts is a separate,
opt-in mesh behavior (deferred) — it hides *which* version ran unless surfaced, and
adds router complexity the base guarantee does not need.

## Compatibility

Additive. `requested_capability_version` is optional; an invocation without it
resolves exactly as before, so every existing envelope, vector, and conformance
fixture is unchanged. The new reserved code is additive to the closed vocabulary
(the guard set enforces its presence across the registries). A **patch** bump
(v0.7.3): a new optional field + a more precise denial, no existing bytes move.

## Deferred by design

Router **auto-selection** of a compatible version across the mesh (the multi-host
behavior); an **`output_schema` compatibility** assertion (declared vs required
shape); **prerelease / build-metadata** tags (`1.0.0-rc.1`, `+build`); the semver
`0.x` caret special-case beyond the documented `>=0.y.z <0.(y+1).0` reading;
range-to-range intersection (a host advertising its own required-caller range).

## Shipped as

- **Spec v0.7.3** — chp-v0.2.md §1.1 (capability-version negotiation) + pipeline
  gate 2; new `capability_version_unsupported` reserved code.
- **chp-core 0.36.0** — `semver.py` (`version_satisfies`/`best_satisfying`, the
  subset matcher); `InvocationEnvelope.requested_capability_version` +
  `ainvoke(requested_capability_version=…)`; the resolution gate resolves to the
  highest satisfying registered version or denies `capability_version_unsupported`.
- **npm alpha.27** — chp-sdk `semver.ts` (byte-parity port).
- **Vectors + guards** — `version-negotiation.json` (15 semver KATs agree in
  Python + TS SDK + `verify.mjs`); `spec_defines_version_negotiation` +
  `version_negotiation_vector_verifies` (alignment 103 → 105); wire path via the
  in-process `test_capability_version_negotiation` (same resolution gate).

Deferred (unchanged): router auto-selection, `output_schema` compat assertion,
prerelease/build tags, `0.x` caret edge beyond the documented reading, range-to-
range intersection.
