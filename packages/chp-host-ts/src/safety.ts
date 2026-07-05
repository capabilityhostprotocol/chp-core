/**
 * Rule-based safety evaluator (spec/chp-governance-v0.2.md §4.2). Minimal port of
 * the Python reference — enough for the conformance profile: a guardrail whose
 * `requires_human_for` (or exceeded `max_risk_level`) lists a capability blocks it.
 */

import type { JsonValue, RiskTier } from './types.js';

const RISK_ORDER: RiskTier[] = ['low', 'medium', 'high', 'critical'];
const HIGH_RISK_PATTERNS = ['bash', 'exec', 'shell', 'delete', 'drop', 'destroy'];
const LEVEL_SCORE: Record<RiskTier, number> = { low: 0.1, medium: 0.4, high: 0.7, critical: 0.95 };

export interface Guardrail {
  id: string;
  capability_id_pattern: string;
  max_risk_level: RiskTier;
  requires_human_for?: string[];
}

export interface Assessment {
  level: RiskTier;
  score: number;
  recommendation: string;
}

export interface SafetyReport {
  assessment: Assessment;
  approved: boolean;
  blockReason: string | null;
  guardrailsEvaluated: string[];
}

const matches = (id: string, pattern: string): boolean => {
  // fnmatch-style: '*' wildcard, case-insensitive
  const re = new RegExp('^' + pattern.toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  return re.test(id.toLowerCase());
};

export class RuleBasedSafetyEvaluator {
  constructor(private readonly guardrails: Guardrail[] = []) {}

  assess(capabilityId: string): Assessment {
    let score = 0.0;
    const cid = capabilityId.toLowerCase();
    if (HIGH_RISK_PATTERNS.some((p) => cid.includes(p))) score = LEVEL_SCORE.high;
    const level =
      score >= 0.8 ? 'critical' : score >= 0.55 ? 'high' : score >= 0.3 ? 'medium' : 'low';
    const recommendation = { low: 'allow', medium: 'warn', high: 'require_approval', critical: 'block' }[
      level as RiskTier
    ];
    return { level: level as RiskTier, score: Math.round(score * 1000) / 1000, recommendation };
  }

  report(capabilityId: string, _payload: JsonValue): SafetyReport {
    const assessment = this.assess(capabilityId);
    const evaluated: string[] = [];
    for (const g of this.guardrails) {
      if (!matches(capabilityId, g.capability_id_pattern)) continue;
      evaluated.push(g.id);
      if (RISK_ORDER.indexOf(assessment.level) > RISK_ORDER.indexOf(g.max_risk_level)) {
        return { assessment, approved: false, blockReason: `guardrail '${g.id}': risk ${assessment.level} exceeds ${g.max_risk_level}`, guardrailsEvaluated: evaluated };
      }
      if ((g.requires_human_for ?? []).includes(capabilityId)) {
        return { assessment, approved: false, blockReason: `guardrail '${g.id}': '${capabilityId}' requires human approval`, guardrailsEvaluated: evaluated };
      }
    }
    return { assessment, approved: true, blockReason: null, guardrailsEvaluated: evaluated };
  }
}
