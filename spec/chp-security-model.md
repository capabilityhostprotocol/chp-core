# CHP Security Model — Properties, Adversaries, and Residual Risks

Status: **normative** (v0.5.1, 2026-07-12; proposal 0020). Consolidates the
guarantees and honest boundaries stated locally across [chp-v0.2.md](chp-v0.2.md)
§1–§14 and the [proposals/](proposals/). This document is the single answer to
*"what does CHP guarantee, against whom, and what does it explicitly not?"*

CHP is a **governed evidence plane**: it standardizes tamper-evident,
attributable, offline-verifiable evidence for capability invocations. It is not a
sandbox, a policy engine of last resort, or a claim that a host is honest — it
makes what a host *did* (and what it *refused*) **provable** to a third party, and
makes **omission and tampering detectable**. This document is deliberately honest
about the boundary of each guarantee; that honesty is why the protocol is
pre-1.0.

## How to read this

Each mechanism provides a **guarantee** against one or more **adversary classes**
and carries a **residual risk** — the stated limit beyond which the mechanism
makes no claim. A verifier chooses the assurance it requires and **MUST reject a
tier lower than it requires rather than silently degrading** (chp-v0.2.md §1).

## Adversary classes

- **Honest-verifier** — an honest party checking evidence it was given. Baseline:
  can it detect an *accidentally* invalid or malformed record? (correctness).
- **Malicious host / operator** — the party that produced the evidence, acting in
  bad faith after the fact: tampering with its own store, reordering, deleting,
  omitting, or backdating records.
- **Network adversary** — a party on the wire between caller and host: MITM,
  replay, downgrade, strip/staple of unsigned fields.
- **Colluding peers** — witnesses or quorum members the operator controls or
  bribes, countersigning false state.
- **External relying-party** — a party outside the mesh with no trust in the
  operator's peer set, verifying a claim offline.

## Assets & trust boundaries

The protected assets are: **evidence integrity** (records are not silently
mutated/reordered/omitted), **provenance** (which host/key/subject/principal a
record is attributable to), and **authority attribution** (a delegated action is
bound to its principal). The trust boundary is the host's private signing key and
its append-only store; everything a *stranger* must believe is pushed inside a
signature or an external anchor. Confidentiality of payloads is **not** a core
asset (see selective disclosure + the residual risks below).

## Property matrix

Each row: the mechanism, the guarantee, the adversary it defends against, and the
residual risk.

### Integrity & provenance

| Mechanism | Guarantee | vs adversary | Residual risk |
|---|---|---|---|
| **Assurance tiers** (§1) | `none`/`hash-chain`/`signed`; a verifier rejects a lower tier than it requires | honest-verifier, malicious-host | `none` (v0.1) is not tamper-evident; tiers are opt-in |
| **Hash chain** (§2, `chp-event-hash-v1`) | per-correlation SHA-256 chain detects mutation & reordering of recorded events | malicious-host | detects, does not *prevent*; an unrecorded event leaves no trace (see completeness) |
| **Canonicalization** (§2, `chp-stable-v1`, `chp-jcs-v1`) | byte-exact serialization so any implementation computes the identical hash/signature | honest-verifier, network | rule 6: **no floats** in hashed content; RFC 8785 number formatting is unexercised (deferred) |
| **Signed bundles + attestation** (§3) | the signed header binds origin/time/scheme + `root_hash`; the `host_identity` attestation binds `host_id ↔ public_key` | malicious-host, network | proves **integrity, not provenance** by itself — `key_id` binds a key to itself; the attestation is a TOFU floor until an anchor upgrades it |
| **Anchors** (§3.1, `domain` / `did`) | bind the key to an external trust root a never-met verifier can resolve; omit-when-empty makes strip/staple break the signature | external relying-party, network | an attacker-controlled anchor "verifies" against the attacker's root — the **trust decision belongs to the caller** reading the surfaced root; the domain anchor leans on Web-PKI (CA + DNS) |
| **Key lifecycle** (§3.2) | rotation continuity signed by the OLD key; a verifier walks the chain from its OWN pinned key; issuer-only revocation | malicious-host | **offline verifiers cannot see revocations** — there is no global revocation infrastructure |
| **Key custody at rest** (§3, proposal 0017) | a host MAY hold its key passphrase-encrypted — a stolen key file is not a stolen identity | malicious-host (key theft) | a SHOULD, not a MUST; encryption is at-rest only, never changes the wire |

### Authority

| Mechanism | Guarantee | vs adversary | Residual risk |
|---|---|---|---|
| **Governed pipeline** (chp-invocation-pipeline.md) | a fixed, observable gate order; the first failing gate determines the outcome; every rejection is a reserved denial code | honest-verifier | denial **codes** are a vocabulary, not an enforcement of the host's honesty about which gate fired |
| **Mandates + sub-delegation** (§10) | a principal's signed, expiring, capability-scoped grant, verified **offline** against host time; sub-delegation is **monotone attenuation** (narrow scope, shorten window), verified inductively to the root | malicious-host, network | `max_invocations` enforcement is out of scope; a mandate **narrows and attributes, never bypasses** |
| **Revocation + freshness** (§10, §12, `chp-revocation-head-v1`) | issuer-only revocation; the witnessed revocation-set digest makes a **dropped revocation a provable denial of revocation** | malicious-host, colluding-peers | propagation is best-effort by design (no gossip, no global list); an unwitnessed drop is uncatchable |

### Mesh trust fabric

| Mechanism | Guarantee | vs adversary | Residual risk |
|---|---|---|---|
| **Witnessing** (§12, `chp-store-head-v1`) | peers countersign store heads; the receipt lives with the witness, where the operator cannot delete it — **tamper-proof against the operator** | malicious-host | a single witness is a single point of collusion (→ quorum) |
| **Witness quorum** (§12, `chp-witness-quorum-v1`) | ≥ *k* **distinct** identities (deduped by `key_id`) countersigned this exact head | colluding-peers | still depends on OUR peer set; `quorum_short` is an audit verdict, never a gate denial |
| **External anchoring** (§12, `chp-store-head-anchor-v1`) | an out-of-mesh `did:key` SSHSIG-countersigns the head — survives even if every witness colludes | colluding-peers, external relying-party | the signed-checkpoint form; real transparency-log submission + gossip are out of scope |
| **Merkle store head** (§12, `chp-store-head-v2`) | an RFC 6962 Merkle root + inclusion proof lets an **external party verify one correlation's leaf under an anchored root with no leaves and no witness** | external relying-party | Merkle **consistency** proofs (append-only between roots) are out of scope |
| **Completeness / non-omission** (§12, `chp-completeness-v1`) | a bundle asserts it is the complete correlation; a witnessed/anchored head that advanced past the claimed tail is a **provable dropped tail** | malicious-host | an **unwitnessed** tail-truncation is uncatchable — no protocol can force a host to record, or to have had the record witnessed |

### Disclosure, ordering, reliability

| Mechanism | Guarantee | vs adversary | Residual risk |
|---|---|---|---|
| **Selective disclosure** (§14, `chp-event-hash-v2`) | commit a payload by hash so it can be **withheld without re-signing**; a disclosed payload must match its commitment | honest-verifier (privacy) | withhold/minimize is **not** retention redaction; per-field Merkle commitments are deferred |
| **Causal ordering** (`chp-causal-order-v1`) | deterministic causal order across hosts for cross-host bundles | honest-verifier | a total real-time order is not claimed |
| **Idempotent replay + streaming + exactly-once** (§13, `chp-chunk-seq-v1`) | a recorded `invocation_id` MUST NOT re-execute; streaming completion via chunk-sequence evidence | network (replay) | idempotency is a **bounded-window** guarantee; the §11 residual (executed-but-ack-lost across owners) remains |
| **Version negotiation** (§1.1) | a host declares `supported_versions`; an unsupported explicit version is rejected, not silently processed | network (downgrade) | `version_unsupported` is a transport-level rejection with **no evidence**; one wire lineage exists today |

## Denial vocabulary (attribution of refusals)

A governed refusal is attributable to a reserved code, so *"the host refused, and
why"* is itself provable. The reserved codes are `approval_required`,
`budget_exceeded`, `capability_disabled`, `capability_not_found`,
`capability_version_unsupported`, `escalation_required`, `evidence_required`,
`host_unreachable`, `input_schema_validation_failed`, `invariant_failed`,
`mandate_exhausted`, `mandate_invalid`, `output_schema_validation_failed`,
`policy_blocked`, `safety_blocked`,
`unsupported_mode`, `version_unsupported` (see [reserved-names.md](reserved-names.md); the source of
truth is `DenialReason.RESERVED_CODES`). Residual risk: the codes standardize
*which* refusal a host claims, not that the host is honest about having applied
the gate — that honesty is what witnessing and completeness make checkable.

## Verifier robustness (fail-closed)

Every verifier — bundle, attestation, mandate, auth-token, store-head-anchor, rekor
anchor, disclosure receipt, chain-witness, monitor report, continuity/revocation — is
**fail-closed** against untrusted input (proposal 0042): given input of *any* shape
(a non-object, missing/wrong-typed/truncated fields, nonsense nesting), a verifier
returns a clean **invalid** verdict. It never raises (a crash on a hostile payload would
be a denial-of-service — an unauthenticated client could topple a host by POSTing a
malformed bundle) and never *falsely verifies* garbage. This is enforced structurally
(an input-shape guard + a catch that converts any residual error to "invalid") and
regression-tested by a fuzz matrix over every verifier. Residual risk: the property is
"no crash / no false-accept on malformed input," not a proof of the cryptographic
verification logic itself — that rests on the underlying ed25519/ECDSA primitives and
the canonicalization being correct.

## What moved from v0.1 non-goal → shipped

The v0.1 threat model ([docs/security/threat-model-v0.1.md](../docs/security/threat-model-v0.1.md))
listed as **Non-Goals**: tamper-evident ledgers, remote/host attestation,
enterprise identity, retention policy, full policy evaluation, and multi-host
causal ordering. Each has since shipped: witnessing + anchoring + the Merkle head
(tamper-evidence against the operator), host-identity attestation + anchors
(host attestation), the governed pipeline + mandates (policy + authority),
retention with verifiability preservation (§4), and `chp-causal-order-v1`
(multi-host ordering). v0.1's honest core still holds: *"CHP does not prove that a
host is honest; it standardizes the structure a host must emit"* — this document
extends that to *"…and makes dishonesty detectable, up to the stated boundary of
each mechanism."*

## Residual risks — the consolidated non-guarantees

1. **Recording cannot be forced.** No mechanism compels a host to record an
   event; completeness + witnessing make *omission of witnessed state* detectable,
   not the failure to record at all.
2. **Offline revocation blindness.** An offline verifier cannot see revocations;
   freshness makes a *dropped* revocation provable only for witnessed heads.
3. **Anchor trust is the caller's.** An anchor proves *"root R vouches for this
   key/head"*; whether R is trustworthy is the reading party's decision.
4. **Confidentiality is out of scope at the core.** Payloads are integrity-
   protected, not encrypted; selective disclosure withholds, it does not encrypt.
5. **Bounded-window idempotency** and the **executed-but-ack-lost** exactly-once
   residual remain, per §13/§11.
6. **The peer set is ours until anchored.** Witnessing/quorum depend on peers the
   operator influences; external anchoring + the Merkle head are the escape to
   parties outside the mesh.

## Not covered (deferred)

Formal machine-checked proofs; a full STRIDE/LINDDUN treatment; an external
penetration test or audit engagement. This is a guarantees × adversary matrix,
not a formal-methods artifact or a marketing claim of production readiness.
