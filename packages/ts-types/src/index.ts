/**
 * Public TypeScript types for CHP v0.1.
 *
 * The root export is intentionally limited to the open-source protocol surface
 * described by `spec/chp-v0.1.md` and the JSON Schemas in `schemas/`.
 *
 * Internal legacy mesh/governance helpers are available from
 * `@capabilityhostprotocol/types/legacy`.
 *
 * @packageDocumentation
 */

export * from "./v0_1.js";
// The generated reserved-names registry (denial codes + evidence-type
// families) — always in lockstep with the Python reference and
// spec/reserved-names.md via scripts/gen-reserved-names.py.
export * from "./reserved.js";

export const CHP_VERSION = "0.1";
export const VERSION = "0.1.0";
