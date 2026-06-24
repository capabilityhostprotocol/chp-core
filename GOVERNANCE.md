# CHP Governance & the Open / Commercial Boundary

CHP is stewarded by **Project Auxo, Inc.** ("the Company"). This document records
how the project is licensed per-asset and — importantly — where the line sits
between the open core and commercial work, so contributors and adopters always
know what they're getting.

## Per-asset licensing

| Asset | Location | License |
|---|---|---|
| Specification & schemas | `spec/`, `schemas/` | CC BY 4.0 + royalty-free patent grant ([`PATENTS`](PATENTS)) |
| Reference SDK & runtime | `packages/python`, `packages/ts-runtime`, `packages/ts-types`, `packages/chp-host` | Apache-2.0 |
| First-party & community adapters | `packages/chp-adapter-*`, the `chp-adapter-template` repo | Apache-2.0 |
| Conformance suite | `conformance/` | Apache-2.0 |
| Trademarks ("CHP", "CHP-Certified") | — | Retained by the Company ([`TRADEMARK.md`](TRADEMARK.md)) |

The open core is open for good: the Company does **not** intend to relicense or
withdraw already-published Apache-2.0 or CC BY material. The CLA's relicensing
right exists to enable *additional* licensing (e.g., dual licensing), not to
close what is already open.

## What lives here vs. elsewhere

**This repository (and the other public CHP repos) is the open core.** It holds
the protocol, the SDK, the adapters that make the protocol useful, and the
conformance suite. Contributions here are accepted under [`CLA.md`](CLA.md).

**Commercial components are developed in separate, private repositories** and are
**not** accepted into this repo:

- the hosted evidence / verification service ("the notary");
- the cross-organization registry / trust network;
- compliance & attestation products;
- adapters to enterprise or regulated systems built or sold by the Company.

This boundary is deliberate. It keeps the open core genuinely open and
unencumbered, while letting the Company fund CHP's development from services and
products layered *on top of* the protocol — never by restricting the protocol
itself. The licensing of those commercial components (proprietary vs.
source-available/BSL) is decided per-product and is out of scope for this repo.

## Decision-making

While CHP is early (v0.x), the Company maintains the specification and merges
contributions, prioritizing a small, explicit, testable surface (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)). As the ecosystem grows we intend to open
governance further — up to and including moving the specification to a neutral
standards footing — once the model is stable. Optionality to do so is preserved
by the CLA and the per-asset licensing above.
