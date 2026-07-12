# CHP Specification Index

The Capability Host Protocol (CHP) specification is a set of layered documents.
**Reading order for a new implementer:**

| # | Document | Layer | Version | Status |
|---|---|---|---|---|
| 1 | [chp-v0.1.md](chp-v0.1.md) | Core object model: capabilities, hosts, envelopes, evidence, correlation, replay, outcomes, denial semantics, conformance MUSTs | 0.1 | **stable** (2026-07-06) |
| 2 | [chp-governance-v0.2.md](chp-governance-v0.2.md) | Governance vocabulary: reserved denial codes, risk tiers, autonomy/approval/safety/identity event families, namespacing | 0.2–0.2.2 (additive) | **released** (v0.2 2026-07-06; v0.2.1–v0.2.2 2026-07-09) |
| 3 | [chp-invocation-pipeline.md](chp-invocation-pipeline.md) | The normative 10-gate governed-invocation ordering + per-code trigger predicates | 0.2–0.2.2 (additive) | **released** (v0.2 2026-07-06; v0.2.1–v0.2.2 2026-07-09) |
| 4 | [chp-http-binding.md](chp-http-binding.md) | The HTTP wire binding: routes, auth, the 200-for-processed rule, conformance fixtures | 0.2–0.2.2 (additive) | **released** (v0.2 2026-07-06; v0.2.1–v0.2.2 2026-07-09) |
| 5 | [chp-v0.2.md](chp-v0.2.md) | Evidence integrity: assurance tiers, chp-stable-v1 canonicalization, hash chains, signed bundles, anchors (§3.1), key lifecycle (§3.2) | 0.2–0.2.2 (additive) | **released** (v0.2 2026-07-06; v0.2.1–v0.2.2 2026-07-09) |
| 6 | [reserved-names.md](reserved-names.md) | Generated registry of reserved event types, denial codes, anchor types, prefixes | — | generated |
| 7 | [test-vectors/](test-vectors/) | Byte-exact fixtures + `verify.mjs` (the stdlib reference verifier). Regenerate with `scripts/gen-test-vectors.py` | — | pinned |

Supporting: [CHANGELOG.md](CHANGELOG.md) (protocol history) ·
[proposals/](proposals/) (how the protocol evolves) ·
[`schemas/`](../schemas/) (JSON Schemas for every protocol object) ·
[`conformance/`](../conformance/) (the runner + [FIXTURES.md](../conformance/FIXTURES.md);
`--suite wire` against a live host is the conformance claim).

## Versioning model

**v0.2 is an additive superset of v0.1** — a v0.1-only host remains conformant
at the `none` assurance tier; the v0.2 layers (integrity tiers, governance
vocabulary, pipeline ordering, anchors, key lifecycle) extend without breaking.
A host serving the v0.2 surface advertises `protocol_version: "0.2"` on `/host`;
a bare v0.1 host advertises `"0.1"`. This additive pattern is *the* evolution
rule — see [proposals/README.md](proposals/README.md).

**Wire-version negotiation** (v0.4.1, [proposals/0016]): a host declares
`supported_versions` on `/host`; a client selects the highest mutually-supported
wire version and MAY declare it via `X-CHP-Version`; a host rejects an
unsupported explicit version with `version_unsupported` rather than silently
degrading. Specified before it is needed — with one additive `0.1 ⊂ 0.2` lineage
the negotiator always selects `0.2`, but the path exists so the first
non-additive change (if ever) travels a proven route. Assurance-*tier*
negotiation (a verifier MUST reject a tier lower than it requires) remains the
other half of the compatibility decision.

## Known issues

- Schema `$id` URLs use the placeholder base `https://chp.dev/schemas/…` which
  does not resolve; schemas resolve locally by path. Standing up the domain (or
  re-pointing `$id`s) is tracked, not yet done.
