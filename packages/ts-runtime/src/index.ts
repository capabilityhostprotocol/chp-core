export { SQLiteEvidenceStore } from "./store.js";
export type { EvidenceEvent, ChainVerificationResult } from "./store.js";

export { LocalCapabilityHost, CapabilityExecutionContext } from "./host.js";
export type {
  CapabilityHandler,
  CapabilityRisk,
  InvokeOptions,
  InvocationResult,
  RuntimeCapabilityDescriptor,
} from "./host.js";

export { evaluatePolicy, loadPolicy } from "./policy.js";
export type { BlockPattern, PolicyConfig, PolicyVerdict } from "./policy.js";

export { newId, utcNow, generateSessionId, generateCorrelationId } from "./session.js";

export const CHP_VERSION = "0.1";
export const VERSION = "0.3.0";
