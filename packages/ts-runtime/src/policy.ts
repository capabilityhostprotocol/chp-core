import { readFileSync, existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";

export interface BlockPattern {
  capability_id: string;
  field: string;
  pattern: string;
  reason: string;
}

export interface PolicyConfig {
  block_capability_ids: string[];
  block_patterns: BlockPattern[];
  max_risk_tier: string | null;
  audit_only: boolean;
  allowed_capability_ids: string[] | null;
}

export interface PolicyVerdict {
  should_block: boolean;
  capability_id: string;
  reason: string | null;
}

const RISK_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function loadPolicy(path?: string): PolicyConfig | null {
  const candidates: string[] = [];
  if (path) {
    candidates.push(path);
  } else {
    const env = process.env["CHP_POLICY_FILE"];
    if (env) candidates.push(env);
    candidates.push(join(".chp", "policy.json"));
    candidates.push(join(homedir(), ".chp", "policy.json"));
  }
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      try {
        const raw = JSON.parse(readFileSync(candidate, "utf-8")) as Record<string, unknown>;
        return parsePolicy(raw);
      } catch {
        // skip malformed
      }
    }
  }
  return null;
}

function parsePolicy(data: Record<string, unknown>): PolicyConfig {
  const rawPatterns = Array.isArray(data["block_patterns"]) ? data["block_patterns"] : [];
  const patterns: BlockPattern[] = (rawPatterns as Record<string, unknown>[]).map((p) => ({
    capability_id: String(p["capability_id"] ?? ""),
    field: String(p["field"] ?? ""),
    pattern: String(p["pattern"] ?? ""),
    reason: String(p["reason"] ?? "blocked by policy pattern"),
  }));
  const allowed = data["allowed_capability_ids"];
  return {
    block_capability_ids: Array.isArray(data["block_capability_ids"])
      ? (data["block_capability_ids"] as string[]).map(String)
      : [],
    block_patterns: patterns,
    max_risk_tier: typeof data["max_risk_tier"] === "string" ? data["max_risk_tier"] : null,
    audit_only: Boolean(data["audit_only"] ?? false),
    allowed_capability_ids: Array.isArray(allowed) ? (allowed as string[]).map(String) : null,
  };
}

export function evaluatePolicy(
  capabilityId: string,
  payload: Record<string, unknown>,
  policy: PolicyConfig,
  opts: { capabilityRisk?: string } = {}
): PolicyVerdict {
  let shouldBlock = false;
  let reason: string | null = null;

  if (policy.allowed_capability_ids !== null) {
    if (!policy.allowed_capability_ids.includes(capabilityId)) {
      shouldBlock = true;
      reason = `capability not in allowlist: ${capabilityId}`;
    }
  }

  if (!shouldBlock && policy.block_capability_ids.includes(capabilityId)) {
    shouldBlock = true;
    reason = `capability blocked by policy: ${capabilityId}`;
  }

  if (!shouldBlock && policy.max_risk_tier != null && opts.capabilityRisk != null) {
    const capOrder = RISK_ORDER[opts.capabilityRisk] ?? -1;
    const maxOrder = RISK_ORDER[policy.max_risk_tier] ?? 99;
    if (capOrder > maxOrder) {
      shouldBlock = true;
      reason = `capability risk '${opts.capabilityRisk}' exceeds max_risk_tier '${policy.max_risk_tier}'`;
    }
  }

  if (!shouldBlock) {
    for (const bp of policy.block_patterns) {
      if (bp.capability_id !== capabilityId) continue;
      const value = String(payload[bp.field] ?? "");
      let matched: boolean;
      try {
        matched = new RegExp(bp.pattern).test(value);
      } catch {
        matched = value.includes(bp.pattern);
      }
      if (matched) {
        shouldBlock = true;
        reason = bp.reason;
        break;
      }
    }
  }

  if (policy.audit_only) {
    return { should_block: false, capability_id: capabilityId, reason };
  }
  return { should_block: shouldBlock, capability_id: capabilityId, reason };
}
