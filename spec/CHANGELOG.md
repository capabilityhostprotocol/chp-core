# CHP Protocol Changelog

Protocol- and schema-level changes only (implementation changes live in package
release notes). Format follows [Keep a Changelog](https://keepachangelog.com/).
Every entry that changes canonical bytes or wire behavior names its regression
gate.

## [0.2] — additive over 0.1 (2026-06 → 2026-07)

### Added
- **Cross-host ordering `chp-causal-order-v1`** (chp-v0.2.md §7): deterministic
  causal topological ordering for a correlation's events across N hosts —
  closes v0.1 §10's "does not define cross-host total ordering". Vector:
  `test-vectors/ordering.json`. *Behavioral note: the gateway's federated
  `/replay` output order changed from wall-clock sort to causal order.*
- **Task bundles** (chp-v0.2.md §8): the cross-host verification unit —
  per-host signed bundles aggregated byte-untouched with a canonical member
  order and a `task_root_hash` fingerprint; verification includes causal
  closure + acyclicity; completeness limit stated normatively. Vector:
  `test-vectors/task-bundle.json`; schema `task-bundle.schema.json`.
- **`GET /export/{correlation_id}`** (http-binding §4a): single-host signed
  bundle export; on a gateway, the assembled task bundle (503 on partial —
  never silently-partial evidence). Gateway `/verify` upgraded to federated
  task-bundle verification (`mode: "federated"`), note-fallback retained.
- Correlation-context clarifications (§7): `trace_id` optional/W3C-aligned,
  `baggage` reserved, `parent_correlation_id` informative session-threading.
- **Evidence integrity tiers** (`none` / `hash-chain` / `signed`) with per-event
  `content_hash`/`prev_hash` chains and ed25519-signed bundles; signature covers
  the canonical bundle *header*, not just `root_hash` (chp-v0.2.md §1–3).
- **`chp-stable-v1` canonicalization**, byte-specified with published test
  vectors and a stdlib Node reference verifier (`test-vectors/verify.mjs`) —
  cross-language interop is vector-proven.
- **Governance vocabulary** (chp-governance-v0.2.md): reserved denial-code
  registry, risk-tier semantics/ordering, autonomy/approval/safety/incident/
  compliance/identity event families, reverse-DNS extension namespacing.
- **Normative invocation pipeline** (chp-invocation-pipeline.md): the 10-gate
  ordering + per-code trigger predicates (`capability_disabled` → `skipped`;
  `action_limit` counts only `execution_started`).
- **HTTP wire binding** (chp-http-binding.md): route table, `X-CHP-Key`
  constant-time auth, the load-bearing "processed invocation → HTTP 200,
  outcome in body" rule, conformance fixture profile.
- **Host-identity attestation + authenticated subject**: self-signed
  `host_id ↔ public_key` binding with validity windows; verified callers
  override client-asserted subjects.
- **Anchors** (chp-v0.2.md §3.1): external trust roots inside the signed
  attestation claim — `domain` (Web-PKI via `/.well-known/chp-identity`) and
  `did` (Radicle did:key SSHSIG countersignature). Omit-when-empty byte rule
  keeps pre-anchor bundles byte-identical.
- **Key lifecycle** (chp-v0.2.md §3.2): archival, chained rotation with
  continuity statements, self-signed revocation, `IDENTITY_EVIDENCE_TYPES`
  host-self events (the host's chain as its key-transparency log).
- Wire conformance suite: 15 black-box checks incl. the four governance gates
  and the identity document.

### Changed
- **chp-stable-v1 forbids non-integer numbers in canonicalized content**
  (chp-v0.2.md §2 rule 6). Rationale: Python `json.dumps(0.0)` and ECMAScript
  `String(0.0)` produce different bytes — a latent cross-language verification
  break for any governed bundle carrying a safety score. Fractional values are
  string-encoded in hashed payloads. *Gate: all pre-existing vectors unchanged;
  `governance-bundle.json` added as the governed-chain proof.*
- Host descriptor may advertise `protocol_version "0.2"` when serving the v0.2
  surface (schema relaxed from `const "0.1"` to an enum; a bare v0.1 host still
  advertises `"0.1"`).

### Compatibility
- All v0.2 features are **additive**: a v0.1-only host remains conformant at
  the `none` tier. Byte-compat regression gate: `test-vectors/signed-bundle.json`
  must verify unchanged under `verify.mjs` after any canonicalization-adjacent
  change.

## [0.1] — 2026-05/06

Initial draft: capability/host descriptors, invocation envelopes, execution
evidence, correlation requirements, replay semantics, outcome model
(`success`/`failure`/`denied`/`skipped`), denial semantics, the 9 conformance
MUSTs, and 28 JSON Schemas.
