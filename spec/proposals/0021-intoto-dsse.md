# 0021: in-toto / DSSE Attestation Bridge

- **Status:** shipped (spec v0.6.0, chp-core 0.29.0, npm alpha.20)
- **Issue:** rad:7bae04c9
- **Affects:** chp-v0.2.md (a new **§15 Interop — in-toto / DSSE attestations**
  documenting the portable, standards-shaped export of a signed CHP bundle);
  new `dsse-envelope` + `in-toto-statement` schemas. **Additive** — no existing
  wire object, bundle byte, or signature changes; a CHP bundle is *wrapped*, not
  modified. Extends adapter provenance (0001) and the transparency-log Merkle
  head (0019) into the wider supply-chain ecosystem. Spec **v0.5.1 → v0.6.0**.

## Problem

CHP produces signed, offline-verifiable evidence — but in its own bundle format.
The supply-chain and provenance ecosystem (Sigstore, in-toto, SLSA, GUAC) has
standardized on **[in-toto attestations](https://github.com/in-toto/attestation)**
wrapped in a **[DSSE](https://github.com/secure-systems-lab/dsse)** (Dead Simple
Signing Envelope). Today a CHP verifier is the only thing that can check a CHP
bundle. To *"interoperate to lead"* — the differentiated stance — CHP evidence
should be expressible as a **standard in-toto/DSSE attestation** that any
DSSE-aware verifier can check the signature on, while a CHP verifier additionally
re-verifies the embedded evidence. This lets CHP evidence flow into existing
tooling (cosign/Rekor/GUAC) without CHP conceding its richer model.

## Design

A signed CHP bundle → an **in-toto Statement** wrapped in a **DSSE envelope**,
signed by the same host ed25519 key over the DSSE **PAE** (Pre-Authentication
Encoding). Lossless: the whole CHP bundle is the predicate, so the attestation
round-trips back to a bundle a CHP verifier checks natively.

**The Statement** (`in-toto Statement/v1`):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<correlation_id>", "digest": { "sha256": "<root_hash>" } }],
  "predicateType": "https://chp.dev/attestation/evidence-bundle/v1",
  "predicate": { …the signed CHP evidence bundle… }
}
```

`root_hash` is already a SHA-256 hex (`evidence-bundle` schema), so it is a valid
in-toto subject digest — the attestation's subject *is* the correlation's signed
evidence root. The predicate carries the full bundle (host_identity, anchors,
completeness, events) so nothing is lost.

**The DSSE envelope**:

```json
{
  "payload": "<base64(statement JSON)>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [{ "keyid": "<key_id>", "sig": "<base64(ed25519(PAE))>" }]
}
```

**PAE** (the exact bytes signed, per the DSSE spec):
`"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(body) SP body`, where `SP` is
a space, `LEN` is the ASCII-decimal UTF-8 byte length, and `body` is the **raw**
statement bytes (not the base64). The signature is `ed25519(PAE)` under the host
key — the same key that signed the bundle. DSSE owns this serialization, so the
signer bypasses `chp-stable-v1`/`bundle_header` and signs the PAE bytes directly.

**Verification, two levels.** (1) *Any DSSE verifier* — recompute the PAE from
`payloadType` + the decoded `payload` and check `ed25519(PAE)` against the
`keyid`'s public key. (2) *A CHP verifier* additionally decodes the Statement,
takes `predicate` as the bundle, checks `subject[0].digest.sha256 == root_hash`,
and runs the full `verify_bundle` (chain, root, header signature, host identity).
`verify_attestation` returns both, so a caller sees *"the DSSE envelope is
authentic AND the embedded CHP evidence verifies."* The public key comes from the
embedded bundle's `public_key` (which the bundle's `host_identity` self-attests),
so the attestation is self-contained.

## Compatibility

Additive and non-destabilizing. A CHP bundle is unchanged — it is wrapped, and
the wrapper is a separate artifact; every existing bundle, vector, and signature
is byte-identical (the byte gate holds). No new denial code or evidence type. The
new `dsse-envelope` + `in-toto-statement` schemas conform to the upstream
in-toto/DSSE specs (like the OTel/PROV exports, the *output* is governed by its
external standard; CHP ships the schemas for CHP-side validation). A **minor**
bump (v0.6.0) — a new signed-artifact family + a standards interop surface is a
headline capability, though no existing bytes move.

Deferred by design: real Rekor/Sigstore **submission** + transparency-log
inclusion of the attestation (this ships the portable signed artifact, not the
hosted-log upload — the 0019 continuation); an **SLSA provenance** predicate
mapping (a distinct predicateType); a full **W3C PROV-O** graph export (the
`prov.py` sibling); multi-signature DSSE (one host signature today).

## Shipped as

- **Spec v0.6.0** — chp-v0.2.md §15 (the in-toto/DSSE bridge: Statement + DSSE
  envelope + PAE + two-level verification); new `dsse-envelope` +
  `in-toto-statement` schemas.
- **chp-core 0.29.0** — `dsse.py`: `_pae`, `bundle_to_statement`,
  `dsse_sign`/`bundle_to_attestation`, `verify_dsse` (level 1), `verify_attestation`
  (level 2: PAE sig + subject digest + `verify_bundle`), `attestation_to_bundle`
  round-trip; CLI `chp bundle attest` + `chp attest verify`.
- **npm alpha.20** — chp-sdk `dsse.ts` (byte-parity: the Statement body is
  `canon()` = chp-stable-v1, so the PAE + ed25519 signature are byte-identical).
- **Vectors + guards** — `dsse-attestation.json` (verified in Python, the TS SDK,
  and the stdlib `verify.mjs` — the PAE recomputed byte-identically);
  `spec_defines_dsse_bridge` + `attestation_vector_verifies` (alignment 90 → 92).

Deferred (unchanged from Design): real Rekor/Sigstore submission + log inclusion;
an SLSA provenance predicate; a W3C PROV-O graph export; multi-signature DSSE.
