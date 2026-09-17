/**
 * Skill — a portable, signable agent skill (schemas/skill.schema.json,
 * chp-agentkit chp_agentkit/skills.py). An instruction plus a scoped set of
 * capability ids and the agent shape to run them in. The canonical byte
 * serialization is the compatibility surface a provenance signature binds to.
 *
 * @module skill
 */

/** Agent execution shape for a Skill. */
export type SkillAgentType = "chat" | "tool" | "code";

/** A portable, signable agent skill. Mirrors schemas/skill.schema.json. */
export interface Skill {
  /** Skill name (identifier). */
  name: string;
  /** Human-readable description. */
  description: string;
  /** The instruction that drives the skill. */
  instructions: string;
  /** Capability ids the skill's agent may call (fully-qualified for domain caps). */
  tools: string[];
  /** Agent execution shape. */
  agent_type: SkillAgentType;
  /** Model tier; overridden by an explicit model pin. */
  role: string;
  /** Explicit model pin; overrides role. */
  model: string | null;
  /** For signing + distribution. */
  version: string;
}

/**
 * Validate that an object conforms to the Skill interface. Lenient on optional
 * fields (only `name` is structurally required, as in the schema), so a
 * hand-authored skill and a full to_dict() form both pass.
 */
export function isSkill(obj: unknown): obj is Skill {
  if (typeof obj !== "object" || obj === null) return false;
  const s = obj as Record<string, unknown>;
  return (
    typeof s.name === "string" &&
    s.name.length > 0 &&
    (s.tools === undefined || Array.isArray(s.tools))
  );
}
