# 0035: Authorized Discovery

- **Status:** shipped (spec v0.8.8, chp-core 0.45.0, npm alpha.39)
- **Issue:** rad:fdeff505
- **Affects:** chp-v0.2.md §18 (new) — `host.discover()` filters the catalog by caller
  authority. **No new object, no new reserved code, no schema change** (reuses the
  existing `descriptor.policy.allowed_actors`). **Additive:** `caller=None` = unfiltered
  (today's behavior); an anonymous caller is unaffected. Spec **v0.8.7 → v0.8.8**. M2 /
  GAP 2 of the portfolio substrate mandate.

## Problem

Discovery is an **open catalog**: `host.discover()` filters only by capability attribute
(category / namespace / tags / status / risk), never by caller authority. Proposal 0034
made `descriptor.policy.allowed_actors` enforced at *invocation*, but a caller could still
*see* every capability — including ones it may not invoke. CHP Home's explicit
requirement is "an agent discovers only the capabilities it is authorized to invoke."
This is substrate gap GAP 2.

## Design

**Filter the catalog by the verified caller.** `host.discover()` gains an optional
keyword-only `caller: str | None = None`. When set, a capability is **visible** iff its
`descriptor.policy.allowed_actors` is empty/absent (open) **or** includes the caller;
restricted capabilities the caller may not invoke are hidden. This reuses the exact
allowlist the invocation gate reads, so discover and invoke agree.

**The caller is already known.** `/host` and `/capabilities` are **authenticated** GETs —
`_check_auth` runs before them and sets `self._caller` (the mTLS CN/SAN, named API-key, or
signed-token `sub`), the same identity `/invoke` binds. The handlers thread
`self._caller` into `discover()`. An anonymous/unnamed caller (shared key or no auth) has
`caller=None` → unfiltered, backward-compatible. `/health` and `/.well-known/chp-identity`
stay public and disclose no capability data.

**No new denial code.** Authorized discovery **hides** (returns a shorter list); it emits
no denial. The security boundary stays the invocation gate: a caller that guesses a hidden
id and invokes it is still denied `policy_blocked` (proposal 0034) — defense in depth.
Discovery narrows what a caller *sees*; the gate enforces what it may *do*. **Discover ≠
invoke** is thereby expressible via `allowed_actors` without a separate discover-scope.

## Compatibility

Additive and backward-compatible. `caller=None` reproduces today's unfiltered catalog; no
schema change (reuses `allowed_actors`); no new reserved code. Because `allowed_actors` was
dead before proposal 0034, nothing relied on restricted capabilities appearing in
discovery, so hiding them is safe. Cross-host **delegated** discovery (a gateway forwarding
the end-caller's credential so each member filters on the original caller's behalf) is
deliberately **out of scope** — a gateway serves its merged catalog under its own identity;
a later proposal. Three implementations (Python, TS host, stdlib `verify.mjs`) agree via
`spec/test-vectors/authorized-discovery.json`.

## Shipped as

- **Spec:** chp-v0.2.md §18.
- **Vectors:** `spec/test-vectors/authorized-discovery.json` (5 visibility KAT cases).
- **Guards:** `spec_defines_authorized_discovery` + `authorized_discovery_vector_verifies`.
- **Implementations:** Python (`host.discover(caller=)`, `_sync_discover` + the `/host` and
  `/capabilities` handlers thread `self._caller`), TS (`host.discover(caller?)` + the
  `server.ts` routes thread `auth.caller.name`), `verify.mjs` matcher. Test:
  `test_authorized_discovery.py`.
