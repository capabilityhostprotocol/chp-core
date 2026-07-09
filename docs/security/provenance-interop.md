# CHP Adapter Provenance × Sigstore / SLSA / PEP 740

How CHP's supply-chain layer (spec/chp-v0.2.md §9) relates to the wider
software-provenance ecosystem — what maps cleanly, what CHP adds, and how the
systems can interoperate. CHP's stance here mirrors its OTel/PROV stance:
interoperate with the ecosystem's rails, differentiate on the governed,
evidence-linked layer above them.

## Concept mapping

| CHP (§9) | Sigstore | SLSA | PEP 740 (PyPI) |
|---|---|---|---|
| `adapter-provenance` statement | DSSE envelope over an in-toto statement | Provenance predicate | Publish attestation |
| `wheel_sha256` (signed, pre-execution) | Subject digest | `subject.digest` | Distribution digest |
| Publisher `host_identity` attestation + anchors (§3.1) | Fulcio certificate (OIDC identity binding) | Builder identity | Trusted Publisher identity |
| DID / domain anchor | Certificate identity claims (issuer + SAN) | — | GitHub repo/workflow claims |
| `~/.chp/publishers.json` pin (TOFU / pinned / rotated / anchored) | Trust root config (TUF-delivered) | Verifier policy | Installer policy (PEP 740 verification) |
| `key_history` continuity walk (§3.2) | Certificate re-issuance (keyless — no continuity needed) | — | — |
| `host_adapter_installed` / `host_adapter_install_rejected` **evidence** | ✗ (Rekor logs the signing, not the *consumption*) | ✗ | ✗ |

## What maps cleanly

- **The claim shape is the same everywhere**: *identity X asserts artifact
  digest D corresponds to (package, version)*. A CHP statement is convertible
  to an in-toto/SLSA provenance predicate mechanically (subject = the wheel
  digest; the CHP publisher attestation populates the builder/identity field).
- **Keyless vs keyful is a root choice, not a model difference.** Sigstore
  binds signing to an OIDC identity via short-lived Fulcio certs; CHP binds a
  long-lived ed25519 key to external roots via anchors (domain Web-PKI, or a
  Radicle DID countersignature). Both answer "whose?" through a resolvable
  root; CHP's works fully offline (the DID anchor verifies with no network,
  no CA) and in decentralized settings where OIDC issuers don't exist.

## What CHP adds that the others do not

The ecosystem tools stop at *publication*: the artifact was signed, the log
recorded it. CHP's differentiator is that **consumption is governed evidence
on the same signed plane as everything else the agent did**: the install (or
refusal) is a hash-chained, signable, correlation-linked event
(`SUPPLY_CHAIN_EVIDENCE_TYPES`), riding the submitting invocation's causal
chain (§7). "Which agent caused which code to be installed on which host,
under whose approval, and what was refused" is a replayable query — that
last mile is out of scope for sigstore/SLSA by design.

## Current SLSA posture (honest)

The reference pipeline today is roughly **SLSA Build L1** (provenance exists,
is available, and is verified at install), with the *identity* leg stronger
than L1 implies (anchored keys, not bare assertions). It is **not L2+**: the
publisher signs artifacts operator-side, not from a hosted build service, and
CHP statements are not yet transparency-logged. The documented path upward:

1. **PEP 740 / Trusted Publishing attestations** — the packages already
   publish via PyPI Trusted Publishing (OIDC); enabling attestations gives a
   sigstore-backed, build-service-signed claim *in parallel* with CHP
   statements. Verifiers could then require both: PEP 740 for build
   integrity, CHP for anchored publisher identity + consumption evidence.
2. **Rekor submission** of CHP statements (they are canonical JSON; DSSE
   wrapping is mechanical) for transparency-log inclusion.
3. **Emitting SLSA provenance predicates** from `chp provenance sign` as a
   sibling output, for consumers that speak SLSA natively.

None of these replace §9 — they add rails under it. The order above is the
recommended adoption order if/when demand appears.

## Verification interop today

A CHP statement can be verified with zero CHP infrastructure: it is canonical
JSON (`chp-stable-v1`), ed25519 over the header, with the reference stdlib
verifier (`spec/test-vectors/verify.mjs`) as an executable specification.
Conversely, a consumer that only trusts sigstore can ignore CHP statements
and still install the same artifacts — §9 is additive, per the compatibility
rule in [proposals/0001](../../spec/proposals/0001-adapter-provenance.md).
