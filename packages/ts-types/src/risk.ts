/**
 * Risk Classification Types
 *
 * Risk classes determine the level of governance scrutiny applied to a capability.
 * Higher risk classes require stronger assurance and more evidence.
 *
 * @module risk
 */

/**
 * Risk classification for capabilities.
 *
 * Ordered from lowest to highest risk:
 * - INFORMATIONAL: Read-only, no side effects
 * - LOW: Minor side effects, easily reversible
 * - MEDIUM: Moderate side effects, may require coordination
 * - HIGH: Significant side effects, requires authorization
 * - CRITICAL: System-wide impact, requires multi-party approval
 */
export type RiskClass =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

/**
 * Risk class values as a const array for iteration.
 */
export const RISK_CLASSES = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
] as const;

/**
 * Risk class numeric order for comparison.
 */
export const RISK_CLASS_ORDER: Record<RiskClass, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Compare two risk classes.
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function compareRiskClass(a: RiskClass, b: RiskClass): number {
  return RISK_CLASS_ORDER[a] - RISK_CLASS_ORDER[b];
}

/**
 * Check if a risk class is at least as high as another.
 */
export function isRiskAtLeast(actual: RiskClass, required: RiskClass): boolean {
  return RISK_CLASS_ORDER[actual] >= RISK_CLASS_ORDER[required];
}
