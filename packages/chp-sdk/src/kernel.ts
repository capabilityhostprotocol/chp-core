/**
 * Evidence-semantics kernel — TS twins of chp_core's entities / claim-types / trust / assurance
 * (proposal 0044). Behavior parity with the Python kernel: a second implementation agrees on the
 * evidence logic (function-level parity, no shipped vector — the same discipline as assertions.ts).
 *
 * None of this is TRUST-as-a-scalar: assurance dimensions are kept SEPARATE (CHP-TRUST-004), trust is
 * LOCAL and claim-scoped (CHP-TRUST-002), and identity is stable across mutable changes (CHP-ENT-001).
 */

// ---- EntitySubject (CHP-ENT-001/002) ----

export type EntityStatus = 'active' | 'suspended' | 'offboarded';

export interface EntitySubjectInit {
  id: string;
  kind: string;
  status?: EntityStatus;
  display?: Record<string, unknown>;
  identifiers?: Array<Record<string, unknown>>;
  succeedsId?: string | null;
}

/**
 * A durable entity with a STABLE id (CHP-ENT-001). The id survives mutable display / external-identifier
 * / key changes; only an explicit succession creates a NEW entity. External identifiers are evidence-backed
 * CLAIMS, not canonical identity (CHP-ENT-002); kind is informational and grants nothing (CHP-ENT-003).
 */
export class EntitySubject {
  readonly id: string;
  readonly kind: string;
  readonly status: EntityStatus;
  readonly display: Record<string, unknown>;
  readonly identifiers: Array<Record<string, unknown>>;
  readonly succeedsId: string | null;

  constructor(init: EntitySubjectInit) {
    if (init.status && !['active', 'suspended', 'offboarded'].includes(init.status)) {
      throw new Error(`entity status must be active|suspended|offboarded, got ${init.status}`);
    }
    this.id = init.id;
    this.kind = init.kind;
    this.status = init.status ?? 'active';
    this.display = init.display ?? {};
    this.identifiers = init.identifiers ?? [];
    this.succeedsId = init.succeedsId ?? null;
  }

  /** The EntityRef for use as an Assertion/binding subject: {kind, id} — stable identity only, never authority. */
  ref(): { kind: string; id: string } {
    return { kind: this.kind, id: this.id };
  }

  /** Create the SUCCESSOR entity (new durable id) that continues this one — the ONLY way identity changes
   * (CHP-ENT-001). Rotation / profile changes do NOT use this; they keep the same entity. */
  succeed(newId: string, overrides: Partial<EntitySubjectInit> = {}): EntitySubject {
    return new EntitySubject({ kind: this.kind, display: { ...this.display }, ...overrides, id: newId, succeedsId: this.id });
  }
}

// ---- ClaimType (CHP-SEM-002/003) ----

export interface ClaimTypeInit {
  id: string;
  version: string;
  valueSchema: Record<string, unknown>;
  description: string;
  subjectKinds?: string[];
  namespaceAuthority?: Record<string, unknown> | null;
}

/**
 * A canonical, versioned claim type. An EXTENSION claim type (outside the core "chp." namespace) MUST
 * declare its namespace_authority — WHO owns the definition — so it cannot masquerade as unowned/core
 * (CHP-SEM-003). Core "chp.*" types are protocol-authored and need none.
 */
export class ClaimType {
  readonly id: string;
  readonly version: string;
  readonly valueSchema: Record<string, unknown>;
  readonly description: string;
  readonly subjectKinds: string[];
  readonly namespaceAuthority: Record<string, unknown> | null;

  constructor(init: ClaimTypeInit) {
    if (!init.id.startsWith('chp.') && (init.namespaceAuthority == null)) {
      throw new Error(`extension claim type ${init.id} MUST declare a namespaceAuthority (CHP-SEM-003)`);
    }
    this.id = init.id;
    this.version = init.version;
    this.valueSchema = init.valueSchema;
    this.description = init.description;
    this.subjectKinds = init.subjectKinds ?? [];
    this.namespaceAuthority = init.namespaceAuthority ?? null;
  }
}

// ---- TrustAnchor + anchoredIssuerTrusted (CHP-TRUST-001/002) ----

/**
 * A relying party's trust root SCOPED to the claim classes it is authoritative for (CHP-TRUST-002).
 * Trust is LOCAL policy, not a global fact; the wildcard "*" means all claim types (the flat-trust
 * escape hatch — use sparingly).
 */
export class TrustAnchor {
  readonly issuer: string;
  readonly claimTypes: string[];

  constructor(issuer: string, claimTypes: string[]) {
    if (!issuer) throw new Error('a trust anchor must name an issuer');
    if (!claimTypes || claimTypes.length === 0) {
      throw new Error("a trust anchor must scope at least one claim type ('*' for all)");
    }
    this.issuer = issuer;
    this.claimTypes = claimTypes;
  }

  /** Whether THIS anchor trusts `issuer` for `claimType` — issuer must match AND the claim type is in scope
   * (or the anchor is a wildcard). */
  trusts(issuer: string, claimType: string): boolean {
    return issuer === this.issuer && (this.claimTypes.includes('*') || this.claimTypes.includes(claimType));
  }
}

/** Whether ANY anchor trusts `issuer` for `claimType` (CHP-TRUST-001/002). Claim-scoped: an issuer trusted
 * for one claim type is not trusted for another unless an anchor names it. Integrity verification is
 * separate (CHP-VER-011) — this answers trust policy only. */
export function anchoredIssuerTrusted(anchors: TrustAnchor[], issuer: string, claimType: string): boolean {
  return anchors.some((a) => a.trusts(issuer, claimType));
}

// ---- AssuranceVector (CHP-TRUST-004) ----

export type FourState = 'satisfied' | 'unsatisfied' | 'unknown' | 'error';

/**
 * The assurance of a claim across its dimensions, none reduced to a scalar (CHP-TRUST-004). `checks` is the
 * per-check four-state (integrity/subject_binding/…); `issuerAuthority` is the SEPARATE trust decision
 * (CHP-VER-011); `corroboration` the independent-source count (CHP-TRUST-006); `effect` the determination.
 * Deliberately NO score(): a rollup would BE the forbidden scalar. A product may derive a label FROM this,
 * traceable back (CHP-TRUST-012), but not here.
 */
export interface AssuranceVector {
  checks: Record<string, FourState>;
  issuerAuthority: FourState | 'unknown';
  corroboration: number;
  effect?: string | null;
  conflicts: unknown[];
}

export const ASSURANCE_DIMENSIONS = [
  'integrity', 'issuer_identity', 'issuer_authority', 'subject_binding', 'value_binding',
  'freshness', 'revocation', 'corroboration', 'effect',
] as const;

/** Assemble the assurance vector from evidence that ALREADY exists (CHP-TRUST-004) — a projection that
 * re-derives nothing and rolls nothing up; it only carries the dimensions together. */
export function assuranceFrom(
  verification: { checks?: Record<string, FourState> } | null | undefined,
  opts: { issuerAuthority?: FourState | 'unknown'; corroboration?: number; effect?: string | null; conflicts?: unknown[] } = {},
): AssuranceVector {
  return {
    checks: { ...(verification?.checks ?? {}) },
    issuerAuthority: opts.issuerAuthority ?? 'unknown',
    corroboration: opts.corroboration ?? 0,
    effect: opts.effect ?? null,
    conflicts: opts.conflicts ?? [],
  };
}
