/**
 * Capability Declaration Types
 *
 * Capabilities are the units of authority in CHP.
 * This module defines the canonical capability declaration structure.
 *
 * @module capability
 */

import type { RiskClass } from "./risk.js";
import type { AssuranceTier } from "./assurance.js";
import type { DeclaredInvariant } from "./invariants.js";
import type { EvidenceType } from "./evidence.js";

/**
 * Metadata for a declared capability.
 *
 * This is the canonical record of what a capability is, what it can do,
 * and what governance applies to it.
 */
export interface CapabilityDeclaration {
  /** Unique capability identifier (e.g., "payment.process") */
  name: string;

  /** Semantic version string (e.g., "1.0.0") */
  version: string;

  /** Risk classification (INFORMATIONAL to CRITICAL) */
  risk_class: RiskClass;

  /** Human-readable description */
  description: string;

  /** Constraints that must hold for execution */
  invariants: DeclaredInvariant[];

  /** Evidence types this capability produces */
  evidence_types: EvidenceType[];

  /** Whether invocation requires authorization */
  require_entitlement: boolean;

  /** Minimum assurance tier for execution */
  minimum_tier: AssuranceTier;

  /** Team or individual responsible */
  owner: string | null;

  /** Categorization tags */
  tags: string[];
}

/**
 * Get the full capability identifier with version.
 */
export function getCapabilityId(decl: CapabilityDeclaration): string {
  return `${decl.name}:${decl.version}`;
}

/**
 * Create a new capability declaration.
 */
export function createCapabilityDeclaration(params: {
  name: string;
  version?: string;
  risk_class?: RiskClass;
  description?: string;
  invariants?: DeclaredInvariant[];
  evidence_types?: EvidenceType[];
  require_entitlement?: boolean;
  minimum_tier?: AssuranceTier;
  owner?: string | null;
  tags?: string[];
}): CapabilityDeclaration {
  return {
    name: params.name,
    version: params.version ?? "1.0.0",
    risk_class: params.risk_class ?? "medium",
    description: params.description ?? "",
    invariants: params.invariants ?? [],
    evidence_types: params.evidence_types ?? [],
    require_entitlement: params.require_entitlement ?? false,
    minimum_tier: params.minimum_tier ?? "S1",
    owner: params.owner ?? null,
    tags: params.tags ?? [],
  };
}

/**
 * Validate that an object conforms to the CapabilityDeclaration interface.
 */
export function isCapabilityDeclaration(
  obj: unknown
): obj is CapabilityDeclaration {
  if (typeof obj !== "object" || obj === null) return false;

  const c = obj as Record<string, unknown>;
  return (
    typeof c.name === "string" &&
    typeof c.version === "string" &&
    typeof c.risk_class === "string" &&
    typeof c.require_entitlement === "boolean"
  );
}

/**
 * Supported invocation modes for a capability.
 */
export type InvocationMode =
  | "sync" // Synchronous request/response
  | "async" // Asynchronous with callback/promise
  | "stream" // Streaming response
  | "fire_and_forget"; // No response expected

/**
 * Invocation modes as a const array.
 */
export const INVOCATION_MODES = [
  "sync",
  "async",
  "stream",
  "fire_and_forget",
] as const;

/**
 * Host identity for capability hosting.
 * Identifies where capabilities are hosted.
 */
export interface HostIdentity {
  /** Unique host identifier */
  host_id: string;

  /** Host type (server, edge, agent, etc.) */
  host_type: string;

  /** Host version/build */
  version: string;

  /** Environment (production, staging, development) */
  environment: string;

  /** Additional host metadata */
  metadata: Record<string, unknown>;
}

/**
 * Create a new host identity.
 */
export function createHostIdentity(params: {
  host_id: string;
  host_type?: string;
  version?: string;
  environment?: string;
  metadata?: Record<string, unknown>;
}): HostIdentity {
  return {
    host_id: params.host_id,
    host_type: params.host_type ?? "server",
    version: params.version ?? "1.0.0",
    environment: params.environment ?? "development",
    metadata: params.metadata ?? {},
  };
}
