/**
 * Assurance Tier Types
 *
 * Three-tier assurance model for execution trust.
 * Each tier provides increasing levels of confidence in execution evidence.
 *
 * @module assurance
 */

/**
 * Assurance tiers for execution trust.
 *
 * - S1: Observational - Execution was observed by the host
 * - S2: Structural - Deterministic replay is possible
 * - S3: Attested - Cryptographic proof with verified environment
 */
export type AssuranceTier = "S1" | "S2" | "S3";

/**
 * Assurance tier values as a const array.
 */
export const ASSURANCE_TIERS = ["S1", "S2", "S3"] as const;

/**
 * Human-readable names for assurance tiers.
 */
export const ASSURANCE_TIER_DISPLAY_NAMES: Record<AssuranceTier, string> = {
  S1: "Observational",
  S2: "Structural",
  S3: "Attested",
};

/**
 * Assurance tier numeric order for comparison.
 */
export const ASSURANCE_TIER_ORDER: Record<AssuranceTier, number> = {
  S1: 1,
  S2: 2,
  S3: 3,
};

/**
 * Compare two assurance tiers.
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function compareAssuranceTier(a: AssuranceTier, b: AssuranceTier): number {
  return ASSURANCE_TIER_ORDER[a] - ASSURANCE_TIER_ORDER[b];
}

/**
 * Check if an assurance tier meets a minimum requirement.
 */
export function meetsAssuranceTier(
  actual: AssuranceTier,
  required: AssuranceTier
): boolean {
  return ASSURANCE_TIER_ORDER[actual] >= ASSURANCE_TIER_ORDER[required];
}

/**
 * Get the display name for an assurance tier.
 */
export function getAssuranceTierDisplayName(tier: AssuranceTier): string {
  return ASSURANCE_TIER_DISPLAY_NAMES[tier];
}
