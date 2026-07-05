# CHP And W3C PROV

W3C PROV (and de-facto lineage formats like OpenLineage) model **provenance** —
the record of entities, the activities that used or produced them, and the
agents responsible. CHP's evidence is provenance too: a capability invocation is
an *Activity*, its `subject` an *Agent*, its inputs/outputs *Entities*, and its
correlation/causation edges the activity-to-activity links.

So CHP and PROV overlap in what they describe. They differ in three ways that
matter, and all three favor CHP for governing agents:

1. **Active vs passive.** PROV is an after-the-fact description of what happened,
   assembled by tooling. CHP evidence is emitted *at the boundary, as it
   happens*, as a mandatory contract of the host — not reconstructed later.

2. **Governed vs history-only.** PROV records what *was done*. CHP also records
   what was **refused and why** — denial, policy decisions, risk-tier and safety
   evaluations, and human approvals are first-class events on the same record.
   PROV has no vocabulary for a refusal; CHP treats it as evidence.

3. **Signed vs unsigned.** PROV and OpenLineage carry no integrity model —
   provenance you cannot prove wasn't edited. CHP's `signed` assurance tier makes
   the lineage **tamper-evident** (hash chain + ed25519). "Signed, governed
   provenance" is an advance over PROV, not a copy of it.

CHP is expressible *as* PROV for its positive history (Activity / Entity / Agent),
and can export to PROV / OpenLineage to interoperate with lineage and catalog
tooling — adding the governance and integrity those standards lack. CHP is the
active, governed, **signed** provenance plane; PROV is the passive, unsigned
description CHP can feed.
