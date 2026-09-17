/**
 * AgentProfile — a named worker or a whole swarm (schemas/agent-profile.schema.json,
 * chp-agentkit chp_agentkit/profiles.py). A role (model tier) + the capabilities it
 * may use + its skills; a 'manager' profile also carries 'managed' sub-profiles it
 * delegates to. Pure data every product can build and extend; the canonical byte
 * serialization is a signable, portable artifact exactly like a Skill.
 *
 * @module agent-profile
 */

import type { Skill } from "./skill.js";

/** How a profile is executed / composed. */
export type AgentType = "tool" | "code" | "manager";

/** Delegation vs sequential-skill execution. */
export type AgentMode = "manager" | "sequential";

/** A named worker (or a whole swarm). Mirrors schemas/agent-profile.schema.json. */
export interface AgentProfile {
  /** Profile id (identifier). */
  id: string;
  /** Model tier; overridden by an explicit model pin. */
  role: string;
  /** Human-readable description. */
  description: string;
  /** Capability ids this profile may use (its own). */
  tools: string[];
  /** Skills this profile carries. */
  skills: Skill[];
  /** Sub-workers a manager delegates to (recursive). */
  managed: AgentProfile[];
  /** Agent execution shape. */
  agent_type: AgentType;
  /** Explicit model pin; overrides role tiering. */
  model: string | null;
  /** Preferred node to run on; the product routes to it. */
  node: string | null;
  /** System voice seeded ahead of the task. */
  persona: string;
  /** Extra task-seed instructions. */
  instructions: string;
  /** manager = delegate to `managed`; sequential = run skills in order. */
  mode: AgentMode;
  /** Per-skill task overrides (sequential mode). */
  skill_tasks: Record<string, string>;
  /** For signing + distribution. */
  version: string;
}

/**
 * Validate that an object conforms to the AgentProfile interface. Lenient on
 * optional fields (only `id` is structurally required, as in the schema).
 */
export function isAgentProfile(obj: unknown): obj is AgentProfile {
  if (typeof obj !== "object" || obj === null) return false;
  const p = obj as Record<string, unknown>;
  return (
    typeof p.id === "string" &&
    p.id.length > 0 &&
    (p.tools === undefined || Array.isArray(p.tools)) &&
    (p.skills === undefined || Array.isArray(p.skills)) &&
    (p.managed === undefined || Array.isArray(p.managed))
  );
}
