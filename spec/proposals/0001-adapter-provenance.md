# 0001: Signed Adapter Provenance

- **Status:** proposal
- **Issue:** rad:42d7152
- **Affects:** chp-governance-v0.2.md (adapter namespace §5, new provenance §), reserved-names (event types), host wire surface (install path); canonical bytes: **no** (new signed statement object, additive)

## Problem

Adapters are the code that *produces* CHP evidence, yet they install on trust:
`chp.adapters.host.install_adapter` is a plain `pip install` of whatever the
release URL serves. The evidence plane is signed; its supply chain is not. The
floor shipped with the integrity arc — the install event now carries the
installed distribution's `record_sha256` content fingerprint + resolved source
(`host_adapter_installed`, appended under the submitting correlation) — makes
installs *attributable after the fact*, but nothing lets a node verify **before
loading** that an adapter wheel is the one its publisher built.

## Design

Three pieces, all additive:

1. **Provenance statement** — a chp-stable-v1 canonical object the publisher
   signs with their CHP host key (the same ed25519 + attestation machinery as
   evidence bundles):

   ```json
   {
     "kind": "adapter-provenance",
     "package": "chp-adapter-mlx",
     "version": "0.8.10",
     "wheel_sha256": "<sha256 of the wheel file>",
     "record_sha256": "<sha256 of the sorted RECORD hash lines>",
     "publisher": { "host_identity": { ...attestation, may carry anchors... } },
     "signature": "<ed25519 over the canonical statement header>"
   }
   ```

   Published beside the wheel (e.g. `<wheel>.chp-provenance.json` on the
   release). The publisher's trust root is their attestation's anchor (domain /
   DID) — the same "whose?" answer as evidence bundles; no new PKI.

2. **Install-time verification** — `install-adapter` gains
   `--require-provenance [--publisher-key <key_id>|--publisher-domain <d>]`:
   fetch the statement, verify signature + attestation (+ anchor when pinned),
   hash the downloaded wheel BEFORE `pip install`, refuse on mismatch. The
   verified statement is embedded in the `host_adapter_installed` evidence
   payload, upgrading the install event from self-reported fingerprint to
   publisher-signed provenance.

3. **Reserved vocabulary** — event `host_adapter_install_rejected` (verification
   failure is evidence, like a denial); registry entries MAY pin
   `publisher_key_id` per adapter so updates require the same publisher.

## Compatibility

Fully opt-in: without `--require-provenance` the behavior is today's (hash
recorded, nothing verified) and an implementation that ignores this proposal
remains conformant. No canonical-byte change to any existing object — the
statement is a new `kind`, versioned by its own field set under the
omit-when-empty rule. Byte-compat gate: all published vectors unchanged; a new
`adapter-provenance.json` vector lands with the implementation.

## Shipped as (fill on landing)

- Spec: —
- Vectors: —
- Guards: —
- Implementations: —
