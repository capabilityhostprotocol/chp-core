/**
 * Legacy/internal TypeScript types for pre-v0.1 CHP work.
 *
 * These exports are retained for internal packages that still use the older
 * mesh/governance model. They are not the public CHP v0.1 protocol surface.
 *
 * @packageDocumentation
 */

export {
  type RiskClass,
  RISK_CLASSES,
  RISK_CLASS_ORDER,
  compareRiskClass,
  isRiskAtLeast,
} from "./risk.js";

export {
  type AssuranceTier,
  ASSURANCE_TIERS,
  ASSURANCE_TIER_DISPLAY_NAMES,
  ASSURANCE_TIER_ORDER,
  compareAssuranceTier,
  meetsAssuranceTier,
  getAssuranceTierDisplayName,
} from "./assurance.js";

export {
  type EvidenceType,
  type Evidence,
  EVIDENCE_TYPES,
  createEvidence,
  isEvidence,
} from "./evidence.js";

export {
  type InvariantClass,
  type EnforcementResponsibility,
  type FailureBehavior,
  type DeclaredInvariant,
  INVARIANT_CLASSES,
  createDeclaredInvariant,
  isDeclaredInvariant,
} from "./invariants.js";

export {
  type SubjectContext,
  type InvocationContext,
  type ExecutionOutcome,
  EXECUTION_OUTCOMES,
  createSubjectContext,
  createInvocationContext,
  hasEntitlement,
} from "./context.js";

export {
  type GovernanceMode,
  type GovernedContext,
  type GovernanceConfig,
  GOVERNANCE_MODES,
  DEVELOPMENT_CONFIG,
  PRODUCTION_CONFIG,
  TESTING_CONFIG,
  blocksExecution,
  emitsEvidence,
  createGovernedContext,
  createGovernanceConfig,
  createChildContext,
  emitEvidence,
  elapsedMs,
} from "./governance.js";

export {
  type CapabilityDeclaration,
  type InvocationMode,
  type HostIdentity,
  INVOCATION_MODES,
  getCapabilityId,
  createCapabilityDeclaration,
  isCapabilityDeclaration,
  createHostIdentity,
} from "./capability.js";

export const LEGACY_CHP_VERSION = "1.0";
