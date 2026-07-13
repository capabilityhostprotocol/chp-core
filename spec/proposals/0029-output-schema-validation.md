# 0029: Output-Schema Validation + Output-Shape Requirement

- **Status:** shipped (spec v0.7.4, chp-core 0.37.0, npm alpha.28)
- **Issue:** rad:31c03c6a
- **Affects:** chp-invocation-pipeline.md (a new POST-execution gate 12) +
  chp-governance-v0.2.md (§2 code table); a new
  **`output_schema_validation_failed`** reserved code + an optional
  `require_output_schema` envelope flag. **Additive** — a capability with no
  `output_schema`, or a host in the default warn mode, is byte-unchanged. Spec
  **v0.7.3 → v0.7.4**.

## Problem

A `CapabilityDescriptor` declares both `input_schema` and `output_schema`. The
host validates the *input* against `input_schema` at pipeline gate 9 and denies
`input_schema_validation_failed` on a mismatch — but `output_schema` is **never
validated**. A capability can silently return a result that violates its own
declared contract, and every downstream consumer (a caller, a composed
capability, an evidence auditor) inherits that unchecked shape. 0028 negotiated
*which version* runs; it explicitly deferred asserting the *output shape* that
version promises. This closes that gap.

## Design

**A post-execution validation gate (gate 12).** After a handler returns
`success` (both the sync and streaming success paths), when `descriptor.output_schema`
is non-empty the host validates the result against it with the same `jsonschema`
already used for input (lazy-imported, no new dependency). This is the mirror of
gate 9, moved after execution because the result only exists once the handler
ran.

**Validate-and-warn by default; strict is opt-in.** A capability that declared a
loose `output_schema` it never actually enforced must not start *failing* the
moment the host begins checking. So the default is **warn**: a violation is
recorded on the `execution_completed` evidence (`output_schema_valid: false` +
`output_schema_error`), the outcome stays `success`, and the result is returned.
Strict mode — where a violation becomes a hard **denial**
(`output_schema_validation_failed`, `retryable: false`, `details` carry
`schema_id` + `path`) — is turned on either:

- **host-wide** via `LocalCapabilityHost(strict_output_schema=True)`, or
- **per-invocation** via the new optional envelope flag `require_output_schema`
  — a *caller* asserting "I require this result to satisfy the declared output
  contract; deny otherwise." This extends 0028: a caller can now negotiate not
  just a compatible capability version but a validated output shape from it.

The warn markers live in the completed evidence, so a violation is always
*provable* on the chain even when it isn't denied — an auditor can find every
capability that broke its own contract without the host having to fail live
traffic.

## Compatibility

Additive. `require_output_schema` is optional and omitted on the wire when False
(its default), so every existing envelope is byte-identical. A capability with an
empty `output_schema` (the common case) skips the gate entirely — no evidence
change. In the default warn mode a conforming result is byte-identical to before;
only a *violating* result gains two marker keys on its completed evidence. The
new reserved code is additive to the closed vocabulary (the guard set enforces it
across the registries). A **patch** bump (v0.7.4): a new optional field, a new
post-execution gate, and a more precise denial — no existing bytes move.

## Deferred by design

`output_schema`-to-`output_schema` **compatibility** between hosts (a caller
advertising a required output shape and the host intersecting it against the
capability's declared one — this arc validates the *result*, not shape-vs-shape);
**partial / streaming-chunk** output assertions (each delta validated against an
item schema — this validates the terminal result only); coercion or repair of a
near-miss result; a distinct warn *event type* (the warn markers ride the existing
`execution_completed` evidence rather than adding an event to the closed set).

## Shipped as

- **Spec v0.7.4** — chp-invocation-pipeline.md gate 12 (post-execution output
  validation); chp-governance-v0.2.md §2 gains `output_schema_validation_failed`.
- **chp-core 0.37.0** — `host._validate_output(descriptor, data, envelope)` called
  in both success paths; `InvocationEnvelope.require_output_schema`;
  `LocalCapabilityHost(strict_output_schema=…)`.
- **npm alpha.28** — chp-sdk/host output-validation parity + `verify.mjs`.
- **Vectors + guards** — `output-schema.json` (conforming + violating results
  agree in Python + TS SDK + `verify.mjs`); `spec_defines_output_schema_validation`
  + `output_schema_vector_verifies`; wire path via an in-process test.
