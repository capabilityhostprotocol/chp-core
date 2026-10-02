# 0050: Verdict-free qualification (QualificationClaim)

- **Status:** proposal
- **Issue:** rad:0a33dec559b40665e486acd0f5b96952e5085f83
- **Affects:** spec (supply/Tier C), chp_core types. No canonical bytes, no wire route.

## Problem

CHP already forbids a supply record from encoding a conclusion — `qualified`, `authorized`,
`approved`, `trusted`, `admitted` are contextual and derived at admission, never properties of a
provider (CHP-SUP-002; `supply._FORBIDDEN_CONCLUSIONS`; `discovery._FORBIDDEN`). But there is no
positive type for recording *what was observed about a capability's fitness*. Without one, a
producer either invents an ad-hoc record (and risks smuggling a verdict back in) or overloads a
supply record with conclusions the invariant exists to keep out.

The Capability Foundry makes this concrete and urgent: its qualification lane must emit a record
that says what it checked and what evidence backs it — and must NOT say "qualified: true". The
E1 decision (ratified, commit `6fb09a9e`) is that qualification is modeled as **evidence, not a
boolean**. This proposal gives that decision a type.

## Design

A `QualificationClaim` (chp_core/qualification.py) is a **verdict-free** record of what has been
observed about a subject's fitness **for a stated purpose**:

- `subject` — the capability (or binding) id under assessment.
- `purpose` — the use the fitness is assessed FOR. Qualification is purpose-relative, never
  absolute; fit for one purpose is not fit for another. Required.
- `assessor` — the entity that made the observations.
- `observations` — provenanced records (`{property, value, provenance, evidence?}`) of what was
  seen. They carry **no verdict**.
- `claim_id`, `created_at` — identity and time.

Each observation reuses the supply-side provenance grammar as the single source of truth
(`supply.PROVENANCE` / CHP-SUP-012): `self_asserted` and `inferred` are honest about being unbacked
and need no evidence; `externally_verified` and `execution_derived` make a truth claim about the
world and therefore **MUST cite the evidence that backs them** (assertion / verification-result /
effect ids). The `property` of an observation may never be a conclusion.

**The claim never concludes.** A consumer derives any qualification judgement from the cited
evidence at admission — the claim only reports. `__post_init__` enforces this by construction:
it validates every observation's provenance/evidence discipline and walks the whole serialized
claim to refuse any forbidden-conclusion key set truthy anywhere (so a verdict cannot be smuggled
inside an observation value). This is the new invariant **CHP-SUP-013**.

Per E2, chp_core carries only the *type* and its invariants; the qualification *process* that
produces claims lives adapter-side (the Foundry's `chp-adapter-foundry` ecosystem).

## Compatibility

Purely additive. An implementation that ignores `QualificationClaim` remains fully conformant — no
existing type, schema, wire route, or canonical-byte stream changes. The type reuses existing
supply constants, so there is no new vocabulary to keep in sync beyond CHP-SUP-013 itself. No
byte-compat regression gate is required.

## Shipped as (fill on landing)

- Spec: this proposal; CHP-SUP-013 added to the supply invariant family.
- Guards: `QualificationClaim.__post_init__` (verdict-free by construction) + the observation
  provenance/evidence discipline; a conformance check asserting verdict-freeness is a follow-on.
- Implementations: python `chp_core/qualification.py` (+ `__init__` export); TS second-impl = follow-on.
