# 0017: Key Custody Upgrade — Encrypted-at-Rest Keys + Schema `$id` Consistency

- **Status:** shipped (spec v0.4.2, chp-core 0.25.0; npm unchanged at alpha.17 — no TS changes)
- **Issue:** rad:ec0b7208
- **Affects:** chp-v0.2.md §3 (a note that a signed host MAY hold its key
  **encrypted at rest** — passphrase-wrapped — with no change to any wire
  object); `schemas/*.json` (normalize the two off-domain `$id`s onto the
  canonical base); a new `schema_ids_consistent` alignment guard. **Additive** —
  encryption is purely at-rest, so every signature, attestation, and bundle is
  byte-identical and every published vector verifies unchanged; the schema
  change touches only two self-contained `$id` strings. Two 1.0-readiness
  custody gaps. Spec **v0.4.1 → v0.4.2**.

## Problem

Two custody gaps stand between the current state and a 1.0 host:

1. **Host signing keys are stored unencrypted.** `generate_keypair` writes the
   raw ed25519 seed (base64, `NoEncryption`) to `host_ed25519` at mode `0600`.
   File permissions are the only at-rest protection — a copied key file *is* a
   copied identity, able to forge this host's evidence indefinitely. A 1.0 host
   should be able to hold its key **passphrase-protected at rest** so a stolen
   file is not a stolen identity.

2. **Schema `$id`s are domain-inconsistent** (spec/README.md known issue). 33
   schemas use `https://chp.dev/schemas/v0.{1..4}/…`; **two**
   (`certification-record`, `invocation-metrics`) drift onto
   `https://capabilityhostprotocol.dev/schemas/…` with no version segment. The
   `$id` base is inert at runtime (schemas resolve locally by path; a test
   registry is keyed by `$id`), so the split is latent — but nothing *guards*
   it, so it will drift further.

## Design

**Encrypted-at-rest keys (opt-in).** `generate_keypair(key_dir, *,
passphrase=None)`: when a passphrase is supplied, the private key is serialized
as **PKCS#8 PEM under `BestAvailableEncryption(passphrase)`** (pyca/cryptography,
already the signing backend); when it is `None`, the current Raw+base64 format is
written **unchanged** — so every existing key and the default path are
byte-identical. The format is self-describing: `load_host_key` reads the file and
dispatches on the PEM header (`-----BEGIN`) — encrypted PEM → `load_pem_private_key`
with the passphrase; otherwise the legacy Raw+base64 → `from_private_bytes`. The
passphrase is resolved at load from `$CHP_KEY_PASSPHRASE`, or (interactive) a
`getpass` prompt; an operator MAY source it from the OS keychain and export it
(keychain-as-passphrase-provider — no platform-locked dependency in core). Same
filename, same `0600`, single read chokepoint (`load_host_key`) covering all
15+ signing call sites. `rotate_keypair` preserves the encryption disposition.
The unlocked in-memory key is an ordinary `Ed25519PrivateKey`, so **signatures,
attestations, mandates, witnesses, and bundles are byte-identical** to an
unencrypted key — encryption never reaches the wire. This is **Python host
custody**; the TS SDK holds keys only in memory (no at-rest format to mirror).

**Schema `$id` consistency.** Re-point the two off-domain `$id`s onto the
canonical `https://chp.dev/schemas/v0.X/…` base (they are self-contained — no
`$ref` targets them, so no lockstep `$ref` update is needed). The per-schema
version segment (`v0.1`…`v0.4`, the spec version that introduced each schema) is
coherent and every absolute `$ref` already matches its target's `$id`, so it is
kept. A new `schema_ids_consistent` alignment guard then asserts (a) every `$id`
sits on the single canonical base and (b) every absolute `$ref` resolves to a
registered `$id` — the drift guard that did not exist.

## Compatibility

Additive. The encrypted key format is opt-in; the default keygen and every
existing key file are byte-identical, and encryption is at-rest only — no wire
object, signature, or test vector changes (the byte gate holds). The schema
change rewrites two `$id` strings that nothing references; all 35 schemas still
validate and the test registry still resolves. A **patch** bump (v0.4.2): a
custody recommendation + a schema-hygiene fix, no wire surface added.

Deferred by design: native OS-keychain *storage* of the key itself (vs
keychain-sourced passphrase — the portable path this ships); hardware/HSM or
KMS custody; encrypted-at-rest for the TS SDK (no disk custody there); actually
serving the schemas over HTTP at `chp.dev` (out-of-repo hosting — this proposal
makes the `$id`s consistent and canonical so they *can* be served, it does not
stand up the domain).

## Shipped as

- **Spec v0.4.2** — chp-v0.2.md §3 (a signed host MAY hold its key
  passphrase-encrypted at rest; a custody concern only, byte-identical
  signatures); README known-issue updated (schema `$id`s uniform on the
  canonical base).
- **chp-core 0.25.0** — `generate_keypair(passphrase=)` (PKCS#8
  `BestAvailableEncryption`, else the legacy Raw+base64 default);
  `load_host_key` auto-detects + unlocks (`$CHP_KEY_PASSPHRASE`/prompt);
  `rotate_keypair` preserves the disposition; `chp keygen --encrypt`. The two
  off-domain schema `$id`s normalized; `schema_ids_consistent` guard (alignment
  81 → 82).
- **npm** — unchanged at alpha.17: the encrypted-at-rest format is Python host
  custody; the TS SDK holds keys only in memory, and the wire signature is
  byte-identical, so there is nothing to mirror.
- **Proof** — `test_key_custody.py` shows an encrypted and an unencrypted key
  over the same seed sign byte-identically (encryption never reaches the wire);
  a bundle signed by an encrypted-key host verifies in Python, the TS SDK, and
  the stdlib `verify.mjs` unchanged.

Deferred (unchanged from Design): native OS-keychain storage of the key itself;
HSM/KMS custody; TS at-rest encryption (no disk custody there); serving the
schemas over HTTP at `chp.dev` (out-of-repo hosting).
