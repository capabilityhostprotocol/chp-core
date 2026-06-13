import { randomBytes } from "crypto";

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString("hex")}`;
}

export function utcNow(): string {
  return new Date().toISOString().replace(/\+00:00$/, "Z");
}

export function generateSessionId(projectSlug: string): string {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const hex = randomBytes(3).toString("hex");
  return `agent-${projectSlug}-${date}-${hex}`;
}

export function generateCorrelationId(): string {
  return newId("corr");
}
