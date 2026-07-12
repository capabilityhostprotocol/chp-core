# 0020: Security-Properties / Threat-Model Specification

- **Status:** shipped (spec v0.5.1, chp-core 0.28.0; npm unchanged at alpha.19 — no TS)
- **Issue:** rad:788f5d2b
- **Affects:** a new normative doc **`spec/chp-security-model.md`** (a properties
  matrix — guarantee × adversary × residual-risk — consolidating the guarantee
  and honest-boundary language already scattered across chp-v0.2.md §1–§14 and
  every proposal's "Deferred by design" line); `spec/README.md` (index row);
  `SECURITY.md` (link); `docs/security/threat-model-v0.1.md` (supersede note);
  three `protocol_checks` guards that keep the doc in sync. **No wire change** —
  no schema, canonicalization, hashing, or signing byte moves. Spec **v0.5.0 →
  v0.5.1**.

## Problem

CHP has shipped eighteen mechanisms — tiers, hash chains, signed bundles,
attestations, anchors, key lifecycle + custody, the governed pipeline + denial
vocabulary, mandates + sub-delegation + revocation + freshness, witnessing +
quorum + external anchoring + Merkle inclusion + completeness, selective
disclosure, idempotent replay + exactly-once, version negotiation. Each states,
locally, what it guarantees and (usually) its honest boundary. But there is **no
single normative statement of what CHP guarantees, against which adversary, and
what it explicitly does not.** A relying party — or a skeptic — has to reverse-
engineer the threat model from fourteen sections and twenty proposals. The only
threat-model doc (`docs/security/threat-model-v0.1.md`) is scoped to v0.1, and
every one of its Non-Goals (witnessing, anchors, mandates, causal ordering) has
since shipped. This is the artifact a 1.0-readiness protocol needs — and, given
we are deliberately **not** claiming 1.0, the honest place to say so.

## Design

A normative **`spec/chp-security-model.md`**: a **properties matrix** with

- **adversary classes** (columns): *honest-verifier* (baseline correctness),
  *malicious host/operator* (tampering, omission, backdating), *network
  adversary* (MITM, replay, downgrade), *colluding peers* (witness/quorum
  collusion), *external relying-party* (verification without mesh trust — now
  real via `chp-store-head-v2` inclusion, proposal 0019);
- **mechanism rows**, each mapped to a shipped §/scheme, and each cell stating
  the **guarantee** it provides against that adversary AND the **residual risk**
  in the spec's own words — e.g. "a signed bundle proves *integrity*, not
  *provenance*"; "offline verifiers cannot see revocations"; "an *unwitnessed*
  tail-truncation is uncatchable — no protocol can force a host to record"; "a
  shared key collapses which-host into which-keyholder"; the domain anchor
  "deliberately leans on Web-PKI (CA + DNS)"; "idempotency is a bounded-window
  guarantee."

The doc **supersedes** `docs/security/threat-model-v0.1.md` (which gains a header
pointing here and a note that its Non-Goals shipped), is linked from
`SECURITY.md`'s "Threat model & hardening" section, and is indexed in
`spec/README.md`'s reading-order table.

**Keep-it-honest guards (the teeth).** A prose doc rots; three `protocol_checks`
guards make it a maintained invariant, reusing the
`all(f"\`{c}\`" in doc for c in reserved)` idiom already proven by
`governance_spec_names_denial_codes`:

- `spec_defines_security_model` — the doc exists and defines the adversary
  classes + a residual-risk column;
- `security_model_names_denial_codes` — every code in
  `DenialReason.RESERVED_CODES` is referenced (so a new denial code cannot ship
  without appearing in the threat model);
- `security_model_names_schemes` — every `chp-*-v*` scheme name is referenced.

A future arc that adds a code or scheme but forgets the security matrix fails
alignment — the doc stays honest by construction.

## Compatibility

Additive and non-wire. No schema, canonicalization, hashing, or signing change;
every `spec/test-vectors/` fixture verifies unchanged (the byte gate is trivially
clean). Purely a consolidation doc plus three alignment guards. **Patch** bump
(v0.5.1). No TypeScript change — the SDK/host are unaffected (they stay at their
current alpha); `ts-types` bumps only in version lockstep.

Deferred by design: formal machine-checked proofs; a full STRIDE/LINDDUN
treatment (this is a guarantees×adversary matrix, not a formal-methods artifact);
an external penetration test or audit engagement (an activity, not a spec).

## Shipped as

- **Spec v0.5.1** — `spec/chp-security-model.md` (the properties matrix: 5
  adversary classes × every mechanism, with a guarantee + residual-risk per
  cell); superseded `docs/security/threat-model-v0.1.md`; linked from SECURITY.md;
  indexed in spec/README.md.
- **chp-core 0.28.0** — three `protocol_checks` guards keep the doc honest:
  `spec_defines_security_model` + `security_model_names_denial_codes` +
  `security_model_names_schemes` (alignment 87 → 90). A new denial code or scheme
  cannot ship without appearing in the matrix.
- **npm** — unchanged at alpha.19 (no TS change); `ts-types` bumps only in
  version lockstep.

Deferred (unchanged from Design): formal machine-checked proofs; a full
STRIDE/LINDDUN treatment; an external penetration test / audit engagement.
