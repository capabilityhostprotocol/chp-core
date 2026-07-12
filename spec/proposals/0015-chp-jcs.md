# 0015: chp-jcs-v1 — the Second Canonicalization (RFC 8785)

- **Status:** shipped (spec v0.4.0, chp-core 0.23.0, npm alpha.16)
- **Issue:** rad:88d89d5
- **Affects:** chp-v0.2.md §2 (registers **`chp-jcs-v1`** as a second `canonicalization` scheme + makes the field a dispatch seam); `evidence-bundle` schema (`canonicalization` enum widened). Canonical bytes: **additive** — chp-stable-v1 is the default; a bundle omitting or naming `chp-stable-v1` is byte-identical. First **1.0-readiness** milestone. Spec **v0.3.3 → v0.4.0**.

## Problem

The `canonicalization` field was designed as the evolution seam for CHP's
signing canon — but it is **inert plumbing today**: set to the constant
`chp-stable-v1` everywhere, signed-over (so it is tamper-evident) and
schema-pinned (`enum: ["chp-stable-v1"]`), yet **never dispatched on**.
`verify_bundle` hardcodes the chp-stable-v1 serializer regardless of the field's
value; the reference `verify.mjs` and the TS SDK do the same. A field that
claims to be an evolution seam but that no verifier reads is a latent 1.0 risk —
if the seam does not actually work, the first alternate scheme discovers it too
late. This proposal **proves the seam** by shipping a real second scheme through
it.

## Design

**`chp-jcs-v1`** is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON
Canonicalization Scheme), applied to the same **bundle-header signing canon**
that `canonicalization` already names (the `hash_scheme` axis governing per-event
content-hashes is orthogonal, §2). Over CHP's float-free content it differs from
chp-stable-v1 in exactly three structural ways:

- **Compact separators** `,` / `:` (no spaces), vs chp-stable-v1's `, ` / `: `.
- **Raw UTF-8 strings** — `café`, `🔒` appear literally, vs chp-stable-v1's
  ASCII `\uXXXX` escaping.
- **Keys sorted by UTF-16 code unit** (RFC 8785 §3.2.3), vs chp-stable-v1's
  Unicode code point (Python `sort_keys`). Identical for the Basic Multilingual
  Plane; differs only for astral-plane keys.
- **Numbers:** integers as bare decimal (== chp-stable-v1). §2 **rule 6 (no
  floats in hashed content) is retained across ALL schemes**, so RFC 8785's
  ECMAScript double-to-shortest number algorithm is never exercised by CHP
  content and is a named deferral.

**The dispatch seam.** A single `canon_for(scheme)` returns the serializer for
`chp-stable-v1` or `chp-jcs-v1` (and raises on an unknown scheme). `build_bundle`
takes a `canonicalization` argument; `sign_bundle` signs
`canon_for(bundle.canonicalization)(header)`; `verify_bundle` reads the field and
dispatches the header-signature serializer (absent/legacy → chp-stable-v1). A
chp-jcs-v1 bundle is a **JCS-signed header over `hash_scheme`-hashed events** —
fully coherent, and the event-hash recompute is unchanged. Three
implementations — Python `_canon_jcs`, TS `canonJcs`, and the stdlib `verify.mjs`
— MUST agree byte-for-byte; the seam is "proven" only if a chp-jcs-v1 bundle
verifies in all three.

Scope is the signed **bundle** (the flagship). The `canon_for` dispatcher makes
extending JCS to the other signed statements (mandate, chain-witness,
store-head-anchor, provenance, task-bundle headers) a mechanical follow-up —
their schemas keep `const chp-stable-v1` for now.

## Compatibility

Additive. chp-stable-v1 is the default: a bundle that omits `canonicalization` or
names `chp-stable-v1` is byte-identical, and every published vector and signed
bundle is unchanged. The `evidence-bundle` schema's `canonicalization` enum
widens to `["chp-stable-v1", "chp-jcs-v1"]`; statement schemas stay pinned. No
new denial code or evidence type; the `hash_scheme` (per-event content-hash) axis
is untouched. This is a **minor** spec bump (v0.4.0) because a second
canonicalization scheme is the 1.0-readiness milestone that proves the seam,
even though no existing bytes move.

Deferred by design: RFC 8785 ES double-to-shortest number canonicalization
(unexercised — CHP hashed content is float-free by rule 6, retained across
schemes); JCS event-content-hashes / a JCS-native store (the `hash_scheme` axis
under JCS); statement-level JCS dispatch (mandate/witness/anchor/provenance/task
headers — the `canon_for` dispatcher makes it mechanical).

## Shipped as

- **Spec v0.4.0** — §2 registers `chp-jcs-v1` (RFC 8785) as a second
  `canonicalization` scheme and makes the field a real **dispatch seam**; the
  `evidence-bundle` `canonicalization` enum widens to include it.
- **chp-core 0.23.0** — `signing._canon_jcs` (compact, raw UTF-8, keys by
  UTF-16 code unit) + `_canon_for(scheme)`; `build_bundle` `canonicalization`
  param; `sign_bundle`/`verify_bundle` dispatch the header-signature serializer
  on the field (absent/legacy → chp-stable-v1; unknown → failed signature).
- **npm alpha.16** — chp-sdk `canonJcs`/`canonFor` + `verifyBundle`/`signBundle`
  dispatch; chp-host-ts rides the SDK.
- **Vectors** — `canon/cases-jcs.json` (incl. an astral code-unit key-sort
  case) + `signed-bundle-jcs.json`; verified byte-identically by Python
  `_canon_jcs`, TS `canonJcs`, and the stdlib `verify.mjs`.
- **Guards** — `spec_defines_chp_jcs`, `jcs_canon_cases_verify`,
  `jcs_bundle_verifies` (alignment 76 → 79); wire check
  `check_jcs_canonicalization` (one correlation signed under both schemes,
  both verify, headers differ).

Deferred (unchanged from Design): RFC 8785 ES double-to-shortest number
canonicalization (unexercised — content is float-free by §2 rule 6); JCS
event-content-hashes / a JCS-native store (the `hash_scheme` axis under JCS);
statement-level JCS dispatch (the `_canon_for` dispatcher makes it mechanical).
