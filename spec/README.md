# CHP Specification Index — v0.9 protocol release candidate

The Capability Host Protocol (CHP) is a set of layered documents. This index is the
**v0.9 release candidate for the *protocol*** — the consolidated normative surface as of
**v0.8.3** (33 shipped proposals), frozen additive-only as the RC baseline.

> ## ⚠️ This is a *protocol* RC, not a product v1.0 — read first
>
> "v0.9 RC" means the **wire protocol** is coherent, conformance-covered, and backed by
> two independent implementations — it does **NOT** mean a public production **v1.0**. A
> public v1.0 is a distant milestone gated on production maturity outside this spec: an
> independent **security audit**, **operational hardening** validated under load / soak /
> chaos at scale, a **stability track record** across real third-party deployments,
> adopter-grade docs/SDKs/support, and end-to-end **release/supply-chain integrity**.
> **Many 0.x versions remain.** The 0.x version number is an honest pre-production signal;
> do not read "protocol RC" as "ready to ship 1.0."

## Reading order for a new implementer

| # | Document | Layer | Current version |
|---|---|---|---|
| 1 | [chp-v0.1.md](chp-v0.1.md) | Core object model: capabilities, hosts, envelopes, evidence, correlation, replay, outcomes, denial semantics, conformance MUSTs | 0.1 (stable base) |
| 2 | [chp-v0.2.md](chp-v0.2.md) | Evidence integrity + everything additive since: assurance tiers, canonicalization, hash chains, signed bundles, anchors (§3), key lifecycle, selective disclosure (§14), sealed payloads (§16), mandates (§10), transport/auth + mTLS (§5), Merkle store head (§12), Rekor anchors (§12) | v0.2 → **v0.8.3** |
| 3 | [chp-governance-v0.2.md](chp-governance-v0.2.md) | Governance vocabulary: the reserved denial codes, risk tiers, autonomy/approval/safety/identity event families, namespacing | v0.2 (additive) |
| 4 | [chp-invocation-pipeline.md](chp-invocation-pipeline.md) | The normative **12-gate** governed-invocation ordering + per-code trigger predicates | v0.2 → v0.7.4 |
| 5 | [chp-http-binding.md](chp-http-binding.md) | The **normative** HTTP wire binding: routes, auth (key / token / mTLS), the 200-for-processed rule | v0.2 → v0.8.1 |
| 6 | [chp-transport-bindings.md](chp-transport-bindings.md) | Transport-binding overview: what any binding must preserve; HTTP (normative) + Zenoh (experimental) | overview |
| 7 | [chp-zenoh-binding.md](chp-zenoh-binding.md) | The Zenoh query/reply + pub/sub binding (**experimental**) | v0.8.2 |
| 8 | [chp-security-model.md](chp-security-model.md) | Guarantee × adversary × residual-risk matrix over every mechanism | v0.5.1 |
| 9 | [reserved-names.md](reserved-names.md) | Generated registry of reserved event types, denial codes, anchor types, prefixes | generated |
| 10 | [test-vectors/](test-vectors/) | Byte-exact fixtures + `verify.mjs` (the stdlib reference verifier) | pinned |

Supporting: [CHANGELOG.md](CHANGELOG.md) (protocol history, every entry names its
regression gate) · [proposals/](proposals/) (the 33 numbered proposals + the evolution
rule) · [`schemas/`](../schemas/) (JSON Schemas for every object) ·
[`conformance/`](../conformance/) (the runner; `--suite wire` against a live host is the
conformance claim; `--suite transport` adds live mTLS + Zenoh checks).

## The normative surface at v0.8.3 (one-screen map)

- **Objects:** `InvocationEnvelope`, `InvocationResult`, `ExecutionEvidence`, signed
  `bundle`, `mandate`, `store-head` / `store-head-anchor`, `auth-token`,
  `disclosure-receipt` — each with a JSON Schema in [`schemas/`](../schemas/).
- **Pipeline:** **12 gates** (chp-invocation-pipeline.md) — id → resolution (+ capability
  version negotiation) → enabled → mode → mandate (+ `max_invocations`) → policy →
  invariants → autonomy → input schema → safety → execute → **output schema**.
- **Reserved denial codes (15, closed set):** `capability_not_found`,
  `capability_disabled`, `unsupported_mode`, `policy_blocked`,
  `input_schema_validation_failed`, `output_schema_validation_failed`, `invariant_failed`,
  `budget_exceeded`, `approval_required`, `safety_blocked`, `mandate_invalid`,
  `mandate_exhausted`, `capability_version_unsupported`, `host_unreachable`,
  `version_unsupported`. Source of truth: `DenialReason.RESERVED_CODES` (mirrored in the
  schema + reserved-names.md; a guard enforces all three agree).
- **Canonicalizations (2):** `chp-stable-v1` (default), `chp-jcs-v1` (RFC 8785) — the
  `canonicalization` field dispatches.
- **Evidence-hash schemes:** `chp-event-hash-v1` (inline), `chp-event-hash-v2` (payload
  commitment — enables withhold / seal); **store head** `chp-store-head-v2` (RFC 6962
  Merkle + inclusion/consistency proofs); **sealing** `chp-sealed-v1` (single recipient),
  `chp-sealed-v2` (multi-recipient envelope encryption).
- **Anchor types (open set):** `did` (did:key SSHSIG, offline), `domain` (Web-PKI),
  `rekor` (public transparency-log inclusion). Unknown types = unverifiable provenance,
  never a hard failure.
- **Transport bindings:** **HTTP (normative)** · **Zenoh (experimental)** — both carry
  the identical wire objects; only the carrier differs (chp-transport-bindings.md).

## Versioning model — additive, frozen for the RC

Every change since v0.1 has been **additive** (chp-event-hash-v2 was the one forward-only
commitment change). A v0.1-only host stays conformant at the `none` assurance tier; each
layer extends without breaking. For the v0.9 RC the object model is treated as **frozen —
additive-only**; a non-additive change would be a deliberate major-version event travelling
the wire-version-negotiation path (v0.4.1, [proposals/0016]). This additive discipline is
*the* evolution rule — see [proposals/README.md](proposals/README.md).

## Known issues / deferrals

- **Schema hosting:** `$id`s are uniform on `https://chp.dev/schemas/v0.X/…` and resolve
  locally by path; serving them over the network is an out-of-repo hosting task.
- **Zenoh is experimental:** the Python binding is complete + conformance-checked, but a
  TypeScript `ZenohTransport` (impl #2) is deferred pending a sound
  `zenoh-bridge-remote-api` toolchain. HTTP is the normative binding for the RC.
- **Conformance coverage:** the newer object-level features carry cross-impl *vectors*;
  live `--suite transport` covers mTLS + Zenoh. Broadening live runner coverage of every
  feature is ongoing.
