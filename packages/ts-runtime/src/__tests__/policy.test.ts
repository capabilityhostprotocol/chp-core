import { describe, it, expect } from "vitest";
import { evaluatePolicy, type PolicyConfig } from "../index.js";

const basePolicy: PolicyConfig = {
  block_capability_ids: [],
  block_patterns: [],
  max_risk_tier: null,
  audit_only: false,
  allowed_capability_ids: null,
};

describe("evaluatePolicy", () => {
  it("allows benign commands", () => {
    const policy: PolicyConfig = {
      ...basePolicy,
      block_patterns: [
        { capability_id: "chp.agent.bash", field: "command", pattern: "rm\\s+-rf\\s+(?!/tmp)", reason: "destructive deletion" },
      ],
    };
    const result = evaluatePolicy("chp.agent.bash", { command: "ls -la src/" }, policy);
    expect(result.should_block).toBe(false);
  });

  it("blocks by pattern", () => {
    const policy: PolicyConfig = {
      ...basePolicy,
      block_patterns: [
        { capability_id: "chp.agent.bash", field: "command", pattern: "rm\\s+-rf\\s+(?!/tmp)", reason: "destructive deletion" },
      ],
    };
    const result = evaluatePolicy("chp.agent.bash", { command: "rm -rf /home/user" }, policy);
    expect(result.should_block).toBe(true);
    expect(result.reason).toBe("destructive deletion");
  });

  it("blocks by capability ID", () => {
    const policy: PolicyConfig = {
      ...basePolicy,
      block_capability_ids: ["chp.agent.bash"],
    };
    const result = evaluatePolicy("chp.agent.bash", { command: "ls" }, policy);
    expect(result.should_block).toBe(true);
  });

  it("does not block in audit_only mode", () => {
    const policy: PolicyConfig = {
      ...basePolicy,
      block_capability_ids: ["chp.agent.bash"],
      audit_only: true,
    };
    const result = evaluatePolicy("chp.agent.bash", { command: "ls" }, policy);
    expect(result.should_block).toBe(false);
    expect(result.reason).toBeTruthy();
  });

  it("blocks by risk tier", () => {
    const policy: PolicyConfig = { ...basePolicy, max_risk_tier: "medium" };
    const result = evaluatePolicy("chp.agent.bash", {}, policy, { capabilityRisk: "high" });
    expect(result.should_block).toBe(true);
  });

  it("enforces allowlist", () => {
    const policy: PolicyConfig = { ...basePolicy, allowed_capability_ids: ["chp.agent.file_read"] };
    const result = evaluatePolicy("chp.agent.bash", {}, policy);
    expect(result.should_block).toBe(true);
    expect(result.reason).toContain("allowlist");
  });
});
