# CHP Trademark & Conformance-Mark Policy

> **DRAFT — pending legal review.** Adapted from common open-source trademark
> policies (e.g., the model used by CNCF/Linux Foundation projects) for Project
> Auxo, Inc. Not yet reviewed by counsel.

The names **"Capability Host Protocol"** and **"CHP"**, the CHP logo, and
**"CHP-Certified"** (together, the "Marks") are trademarks of **Project Auxo,
Inc.** ("the Company"). The *code* and *specification* are openly licensed (see
[`NOTICE`](NOTICE)); the *Marks* are not — they are how users know something is
genuinely CHP and trustworthy. This policy explains how you may use them.

The guiding principle: **you may use the Marks to refer to CHP truthfully; you
may not use them in a way that implies endorsement, certification, or origin
that isn't real.**

## You may, without asking (nominative/fair use)

- State that your product "works with CHP", "implements the Capability Host
  Protocol", or "is built on CHP" — if true.
- Use "CHP" in prose, talks, blog posts, and documentation to refer to the
  protocol.
- Use the word marks in the name of a community adapter or tool in a descriptive
  way (e.g., "a CHP adapter for Acme") — provided it does not imply official
  origin (see below).

## You may not, without written permission

- Use the Marks (or confusingly similar names/logos) as the name of your product,
  company, or service, or in a way that suggests the Company produces or endorses
  it.
- Use the Marks on merchandise, domains, or social accounts in a way likely to
  cause confusion about origin.
- Modify the logo, or use it as your own product's icon.
- Claim or imply **certification or conformance** except as allowed below.

## "CHP-Certified" and conformance claims

"CHP-Certified" and "CHP-Conformant" are **certification claims** and are
governed:

- You may state that an implementation **"passes the CHP v0.x conformance
  suite"** if it genuinely passes the suite in [`conformance/`](conformance/) at
  the stated version, and you can show the evidence on request.
- You may **not** use the "CHP-Certified" mark or logo until you are enrolled in
  the certification program operated by the Company (forthcoming). Certification
  ties the claim to a passing conformance run plus a security/quality review, so
  that the mark means something to the people relying on it.

## Adapters

Naming and certification of adapters follow the tiered model in
[`docs/adapter-strategy.md`](docs/adapter-strategy.md). In short: descriptive use
in a community adapter's name is fine; presenting an adapter as *official* or
*certified* requires permission/enrollment.

## Questions & permission requests

Open an issue or contact the maintainers. We grant reasonable requests for
community, educational, and integration use. This policy may evolve; the spirit —
*truthful reference yes, implied endorsement no* — will not.
