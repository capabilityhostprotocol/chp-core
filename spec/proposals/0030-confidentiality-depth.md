# 0030: Confidentiality Depth — Multi-Recipient Sealing + Disclosure Receipts

- **Status:** shipped (spec v0.8.0, chp-core 0.38.0, npm alpha.29)
- **Issue:** rad:a2f47e12
- **Affects:** chp-v0.2.md §16.1 (a new subsection under Sealed Payloads); a new
  **`chp-sealed-v2`** payload-marker scheme + a new **`disclosure-receipt`** signed
  record + schema. **Additive** — a single-recipient seal stays `chp-sealed-v1`
  (byte-identical to 0025); the chain/root/signature verify unchanged. Spec
  **v0.7.4 → v0.8.0** (a minor bump: a new marker scheme + a new signed-record kind,
  the first confidentiality extension since 0025).

## Problem

0025 (`chp-sealed-v1`) seals a payload to exactly **one** recipient — a payload
that N parties must read has to be sealed N separate times (N ciphertexts, N× the
bytes) or not sealed at all. And a sealed payload leaves **no trace of who opened
it**: confidentiality without an accountable disclosure trail. Both were named as
out-of-scope in 0025's §16. This arc delivers them.

## Design

**`chp-sealed-v2` — envelope encryption.** A single random 32-byte **content key**
encrypts `canon(plaintext)` **once** (one `ct`), and the content key is wrapped
**per recipient** by reusing the existing `chp-sealed-v1` seal on the 32-byte key.
The marker is `{scheme: "chp-sealed-v2", nonce, ct, recipients: [{epk, nonce,
wrapped_key}, …]}`. To unseal, a recipient trial-unwraps each `recipients[]` entry
with its X25519 key until one yields the content key, then decrypts the shared
`ct`. Any one of the N recipients reads it; a non-recipient cannot. **The commitment
invariant is untouched** — `payload_commitment` still binds `sha256(canon(plaintext))`,
so the chain, root, and ORIGINAL signature verify offline over the ciphertext with
**no key**, exactly as v1. Zero new dependencies (the wrap is a v1 seal; the content
cipher is the same ChaCha20-Poly1305).

**Disclosure receipts.** A recipient's ed25519-signed record that it unsealed a
specific event: `{kind: "disclosure-receipt", who, content_hash,
payload_commitment, unsealed_at}` with the recipient's signature over the canonical
header — the same signed-record shape as an auth-token (0027) or mandate. Emitted at
the unseal seam (**host-emit-on-unseal**) and persisted alongside the recipient, it
is a non-repudiable disclosure trail over confidential payloads that **never reveals
the plaintext** (it names the payload by its commitment). Verification checks
structure, the signature against the recipient's self-attested key, and that `who`
equals the signing `key_id`; a caller cross-checks `content_hash` /
`payload_commitment` against the bundle to prove the named event exists.

**API.** `seal_payloads(bundle, recipient_enc_pubkey)` widens `recipient_enc_pubkey`
to `str | list[str]` — a bare string stays v1, a list selects v2. `_unseal_bytes`
dispatches on `scheme`. `build_disclosure_receipt` / `verify_disclosure_receipt` in
signing.py. CLI: `chp bundle seal --recipient` is now repeatable (2+ → v2); `chp
bundle unseal --emit-receipt <path>` writes signed receipts for what it disclosed.

## Compatibility

Additive. A single-recipient seal is `chp-sealed-v1`, byte-identical to 0025 — every
existing sealed vector, bundle, and test is unchanged. v2 is opt-in via the list
form. The disclosure receipt is a new standalone signed record (a new schema), not a
change to any existing object. Chain/root/signature semantics are identical to v1
(the commitment invariant is the whole point). A **minor** bump (v0.8.0): a new
marker scheme + a new record kind, no existing bytes move.

## Deferred by design

Receipt **revocation** (a recipient retracting a disclosure claim); **threshold /
k-of-n** unsealing (requiring m recipients to cooperate — v2 is any-of-N);
**per-recipient distinct plaintext** (each recipient sees a different payload — v2 is
one shared plaintext); **forward-secrecy ratchets**; **per-field** sealing within a
payload (still whole-payload). Receipts are a *disclosure* trail, not an access
*control* — v2 does not prevent a recipient from sharing the content key out of band.

## Shipped as

- **Spec v0.8.0** — chp-v0.2.md §16.1 (chp-sealed-v2 + disclosure receipts);
  `schemas/disclosure-receipt.schema.json`.
- **chp-core 0.38.0** — `sealing._seal_bytes_multi` + v2 dispatch in `_unseal_bytes`;
  `seal_payloads` accepts a recipient list; `signing.build_disclosure_receipt` /
  `verify_disclosure_receipt`; CLI repeatable `--recipient` + `--emit-receipt`.
- **npm alpha.29** — `sealing.ts` v2 seal/unseal parity (TS unseals a Python v2
  ciphertext); `verify.mjs` sealed-bundle branch accepts v2.
- **Vectors + guards** — `sealed-bundle-v2.json` (3-recipient, each unseals in Python
  + TS SDK, verify.mjs keyless); guards `spec_defines_confidentiality_depth` +
  `sealed_v2_vector_verifies`.
