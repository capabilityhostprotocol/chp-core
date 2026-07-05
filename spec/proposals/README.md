# How CHP Evolves

The standing rule, promoted from precedent to process:

**Protocol changes are additive.** A new capability of the protocol lands as an
additive tier, vocabulary family, or optional field — never by breaking an
existing conformant host. A host that ignores the addition remains conformant
at its declared floor (the way a v0.1-only host stays conformant at the `none`
assurance tier, and a no-anchor attestation stays byte-identical under the
omit-when-empty rule).

**The regression gate is bytes.** Any change touching canonicalization, hashing,
or signing must leave every published `spec/test-vectors/` fixture verifying
unchanged — or be an explicitly versioned new scheme (the `canonicalization`
field exists so `chp-stable-v1` can be succeeded without breaking history).
Regenerate vectors only via `scripts/gen-test-vectors.py`, and record the change
in [../CHANGELOG.md](../CHANGELOG.md).

**Both implementations move together.** A normative change ships with: spec
text, the Python reference, the TypeScript SDK/host, a test vector, and a
`protocol_checks` alignment guard. If it's wire-visible, the conformance suite
grows a check — a differentiator without a conformance check erodes invisibly.

## Proposing a change

1. Copy [TEMPLATE.md](TEMPLATE.md) to `proposals/NNNN-short-name.md` (next free
   number), status `proposal`.
2. Discussion happens on the Radicle issue the proposal links.
3. On acceptance: status `accepted`; implementation follows the rule above.
4. When shipped: status `shipped`, with pointers to the spec sections, vectors,
   and guards it produced. Superseded proposals get status `superseded` + a
   pointer (do not delete them — see `docs/design/evidence-integrity-v0.2.md`
   for why a stale proposal left unmarked misleads implementers).

Statuses: `proposal → accepted → shipped` (or `rejected` / `superseded`).
