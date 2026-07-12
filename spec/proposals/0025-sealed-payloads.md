# 0025: Sealed Payloads — Payload Confidentiality over the Evidence Chain

- **Status:** shipped (spec v0.7.0, chp-core 0.33.0, npm alpha.24)
- **Issue:** rad:8a1e396e
- **Affects:** chp-v0.2.md (a new **§16 Confidentiality — Sealed Payloads**: a payload
  is encrypted to a recipient's key and the inline payload replaced with a
  `{chp_sealed}` marker — the sibling of §14's `{chp_withheld}`); a new
  `sealed-payload` marker schema + an `enc_public_key` field on the host
  attestation. **Additive** — no hash, root, or signature code changes; the chain
  verifies over the ciphertext exactly as it verifies over a withheld payload.
  **First confidentiality feature** — CHP payloads were integrity-protected but
  plaintext to anyone on the path. Spec **v0.6.3 → v0.7.0** (a new dimension = a
  minor bump, like §15 DSSE was v0.6.0).

## Problem

Every prior arc secured *integrity* — a payload cannot be altered without
detection. But a signed bundle carries its payloads **in the clear**; anyone who
holds or intercepts it reads them. `spec/chp-security-model.md` states it plainly:
*"Confidentiality of payloads is not a core guarantee … integrity-protected, not
encrypted."* For a protocol carrying agent tool-calls — which routinely contain
secrets, credentials, PII, and proprietary prompts — signed-but-readable is a real
limitation. Selective disclosure (0011) lets a holder **withhold** a payload
(drop it, keeping the commitment), but that removes the data entirely; there is no
way to **carry** a payload that only an intended recipient can read while everyone
else still verifies the evidence.

## Design

Sealing is the **exact seam** as withholding. `chp-event-hash-v2` binds an event's
`content_hash` to `payload_commitment = sha256(canon(plaintext))`, *not* to the
inline `payload` (`store.py:57-63`) — which is why `withhold_payloads` can replace
`payload` with `{"chp_withheld": true}` and the chain, root, and signature still
verify with no re-signing (`signing.py:1037-1052`). A **sealed** payload is the
same move with the plaintext *encrypted and carried* instead of dropped.

**`seal_payloads(bundle, recipient_enc_pubkey, predicate)`** (mirrors
`withhold_payloads`): for each v2 event the predicate selects, replace `payload`
with a marker

```json
{ "chp_sealed": { "scheme": "chp-sealed-v1", "epk": "<b64 X25519>",
                  "nonce": "<b64>", "ct": "<b64 AEAD ciphertext>" } }
```

The `payload_commitment` (over the *plaintext*, set at emit — `host.py:997-998`,
unchanged) stays, so `content_hash`/root/signature are untouched.

**`chp-sealed-v1` envelope** — a standard hybrid ECIES:
1. Generate an ephemeral X25519 keypair `(esk, epk)`.
2. `shared = X25519(esk, recipient_enc_pubkey)`.
3. `key = HKDF-SHA256(shared, info="chp-sealed-v1")`.
4. `ct = AEAD_seal(key, nonce, canon(plaintext))` — ChaCha20-Poly1305 (the scheme
   string is the algorithm-agility seam; AES-256-GCM is the alternate).

All four steps use primitives already in the installed `cryptography` lib and
`node:crypto` — **zero new dependencies** (no PyNaCl, no ed25519→x25519 map).

**Verification is unchanged for a third party.** The bundle verifier's
selective-disclosure check (`signing.py:917`, `verify.ts:47-48`) skips a
`{chp_withheld}` payload; it gains the same one-line skip for `{chp_sealed}`. So a
party with **no key** verifies the full chain, root, and signature over the sealed
bundle — the evidence is auditable without disclosing the data. Only the recipient
runs **`unseal_payload(marker, enc_privkey)`** — `X25519(enc_privkey, epk)` →
HKDF → AEAD-open → plaintext — then re-runs the existing commitment check
(`signing.py:919`) to confirm the decrypted plaintext is exactly what the chain
committed. A wrong key fails the AEAD tag; a tampered ciphertext fails the tag; a
swapped plaintext fails the commitment.

**The recipient key.** A host generates a **separate X25519 key** alongside its
ed25519 identity in the key dir (pyca exposes no ed25519→x25519 map, so a distinct
key is the clean path). It publishes the X25519 **public** key as an optional
`enc_public_key` inside `build_attestation` (`signing.py:387-395`), omit-when-empty
exactly like `anchors` (heeding the canonical-vector warning at `signing.py:394`).
Because it lives *inside the signed identity claim*, the sealing key is bound to
`host_id` and cannot be swapped by a MITM. A sender seals to the recipient's
published `host_identity.enc_public_key`.

CLI: `chp bundle seal --bundle <f> --recipient <enc_pubkey> [--out]` and
`chp bundle unseal --bundle <f> [--key-dir]`.

## Compatibility

Additive and non-destabilizing. No hash-scheme, root, header, or signature change —
sealing reuses the v2 commitment seam that already treats the inline payload as
opaque. A sealed bundle is byte-verifiable by any existing verifier that skips the
marker (the one-line addition); an old verifier that doesn't know `chp_sealed`
would try to commitment-check the marker and (correctly) reject it, so the skip is
required in the same release. `enc_public_key` is omit-when-empty, so every
existing attestation/bundle/vector stays byte-identical. A **minor** bump (v0.7.0):
a new signed-artifact *capability* (confidentiality) even though no existing bytes
move.

## Deferred by design

Per-field / sub-payload sealing (seal *part* of a payload — the 0011 per-field
Merkle sibling); **multi-recipient** sealing (one envelope per recipient, or a
group-key wrap); **disclosure receipts** (proving what was unsealed by whom);
sealing non-payload fields; ed25519→x25519 key derivation (would remove the
separate key at the cost of vendoring the birational map — not worth a dependency);
forward secrecy beyond the per-message ephemeral (no ratchet). Confidentiality *in
transit* (TLS/mTLS) remains the transport binding's concern (0027), not this.

## Shipped as

- **Spec v0.7.0** — chp-v0.2.md §16 (sealed payloads, `chp-sealed-v1`,
  `enc_public_key`); new `sealed-payload` marker schema.
- **chp-core 0.33.0** — `sealing.py` (X25519 ECIES `seal_payloads`/`unseal_payload`/
  `unseal_bundle`, key-dir X25519 keygen), `enc_public_key` in
  `build_attestation`/`verify_attestation`, the `{chp_sealed}` verifier skip; CLI
  `chp bundle seal`/`unseal`.
- **npm alpha.24** — chp-sdk `sealing.ts` (byte-compatible via `node:crypto`;
  cross-impl decryption proven — TS unseals Python ciphertext).
- **Vectors + guards** — `sealed-bundle.json` (deterministic; verifies offline
  with no key in Python + TS SDK + stdlib `verify.mjs`; recipient unseals);
  `spec_defines_sealed_payloads` + `sealed_vector_verifies` (alignment 97 → 99).

Deferred (unchanged): per-field sealing, multi-recipient, disclosure receipts,
ed25519→x25519 derivation, forward-secrecy ratchets. In-transit confidentiality is
the transport binding's concern (0027).
