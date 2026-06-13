import Database from "better-sqlite3";
import { createHash } from "crypto";
import { mkdirSync } from "fs";
import { dirname } from "path";
import type { JsonObject } from "@capabilityhostprotocol/types";
import { utcNow } from "./session.js";

export interface EvidenceEvent {
  event_id: string;
  event_type: string;
  invocation_id: string;
  capability_id: string;
  capability_version: string | null;
  host_id: string;
  correlation: { correlation_id: string; [key: string]: unknown };
  timestamp: string;
  sequence: number;
  outcome: string | null;
  payload: JsonObject;
  redacted: boolean;
  error: JsonObject | null;
  denial: JsonObject | null;
  assurance: JsonObject;
}

export interface ChainVerificationResult {
  correlation_id: string;
  event_count: number;
  verified_count: number;
  unverified_count: number;
  valid: boolean;
  first_broken_sequence: number | null;
}

function computeEventHash(event: JsonObject, prevHash: string | null): string {
  const correlation = (event["correlation"] as JsonObject | null) ?? {};
  const stable: JsonObject = {
    event_id: event["event_id"] ?? null,
    event_type: event["event_type"] ?? null,
    invocation_id: event["invocation_id"] ?? null,
    capability_id: event["capability_id"] ?? null,
    host_id: event["host_id"] ?? null,
    correlation_id: (typeof correlation["correlation_id"] === "string" ? correlation["correlation_id"] : null),
    timestamp: event["timestamp"] ?? null,
    outcome: event["outcome"] ?? null,
    payload: event["payload"] ?? null,
    prev_hash: prevHash,
  };
  return createHash("sha256")
    .update(JSON.stringify(stable, Object.keys(stable).sort()))
    .digest("hex");
}

export class SQLiteEvidenceStore {
  private db: Database.Database;

  constructor(path = ".chp/evidence.sqlite") {
    if (path !== ":memory:") {
      try {
        mkdirSync(dirname(path), { recursive: true });
      } catch {
        // ignore — dir may exist
      }
    }
    this.db = new Database(path);
    this._initSchema();
  }

  private _initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS evidence_sequence (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT
      );
      CREATE TABLE IF NOT EXISTS evidence_events (
        sequence INTEGER PRIMARY KEY,
        event_id TEXT UNIQUE NOT NULL,
        event_type TEXT NOT NULL,
        invocation_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        capability_version TEXT,
        host_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        outcome TEXT,
        payload_json TEXT NOT NULL,
        event_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_evidence_correlation
        ON evidence_events(correlation_id, sequence);
      CREATE INDEX IF NOT EXISTS idx_evidence_invocation
        ON evidence_events(invocation_id, sequence);
      CREATE INDEX IF NOT EXISTS idx_evidence_capability
        ON evidence_events(capability_id, sequence);
      CREATE INDEX IF NOT EXISTS idx_evidence_outcome
        ON evidence_events(outcome, sequence);
    `);
    // Graceful migration: add hash columns if missing
    for (const ddl of [
      "ALTER TABLE evidence_events ADD COLUMN content_hash TEXT",
      "ALTER TABLE evidence_events ADD COLUMN prev_hash TEXT",
    ]) {
      try {
        this.db.exec(ddl);
      } catch {
        // column already exists
      }
    }
  }

  append(event: EvidenceEvent): EvidenceEvent {
    const insertSeq = this.db.prepare("INSERT INTO evidence_sequence DEFAULT VALUES");
    const prevRow = this.db
      .prepare(
        "SELECT content_hash FROM evidence_events WHERE correlation_id = ? ORDER BY sequence DESC LIMIT 1"
      )
      .get(event.correlation.correlation_id) as { content_hash: string | null } | undefined;
    const prevHash = prevRow?.content_hash ?? null;

    const tx = this.db.transaction(() => {
      const seqResult = insertSeq.run();
      event.sequence = Number(seqResult.lastInsertRowid);
      const data = eventToJson(event);
      const contentHash = computeEventHash(data, prevHash);
      this.db
        .prepare(`
          INSERT INTO evidence_events (
            sequence, event_id, event_type, invocation_id, capability_id,
            capability_version, host_id, correlation_id, timestamp, outcome,
            payload_json, event_json, content_hash, prev_hash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          event.sequence,
          event.event_id,
          event.event_type,
          event.invocation_id,
          event.capability_id,
          event.capability_version ?? null,
          event.host_id,
          event.correlation.correlation_id,
          event.timestamp,
          event.outcome ?? null,
          JSON.stringify(event.payload),
          JSON.stringify(data),
          contentHash,
          prevHash
        );
    });
    tx();
    return event;
  }

  byCorrelation(correlationId: string): JsonObject[] {
    const rows = this.db
      .prepare(
        "SELECT sequence, event_json FROM evidence_events WHERE correlation_id = ? ORDER BY sequence ASC"
      )
      .all(correlationId) as { sequence: number; event_json: string }[];
    return rows.map((r) => ({ ...JSON.parse(r.event_json), sequence: r.sequence }));
  }

  byInvocation(invocationId: string): JsonObject[] {
    const rows = this.db
      .prepare(
        "SELECT sequence, event_json FROM evidence_events WHERE invocation_id = ? ORDER BY sequence ASC"
      )
      .all(invocationId) as { sequence: number; event_json: string }[];
    return rows.map((r) => ({ ...JSON.parse(r.event_json), sequence: r.sequence }));
  }

  query(opts: {
    capabilityId?: string;
    outcome?: string;
    since?: string;
    until?: string;
    limit?: number;
  } = {}): JsonObject[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts.capabilityId) { clauses.push("capability_id = ?"); params.push(opts.capabilityId); }
    if (opts.outcome) { clauses.push("outcome = ?"); params.push(opts.outcome); }
    if (opts.since) { clauses.push("timestamp >= ?"); params.push(opts.since); }
    if (opts.until) { clauses.push("timestamp <= ?"); params.push(opts.until); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const limitClause = opts.limit != null ? `LIMIT ${opts.limit}` : "";
    const sql = `SELECT sequence, event_json FROM evidence_events ${where} ORDER BY sequence ASC ${limitClause}`.trim();
    const rows = this.db.prepare(sql).all(...params) as { sequence: number; event_json: string }[];
    return rows.map((r) => ({ ...JSON.parse(r.event_json), sequence: r.sequence }));
  }

  verifyChain(correlationId: string): ChainVerificationResult {
    const rows = this.db
      .prepare(
        "SELECT sequence, event_json, content_hash, prev_hash FROM evidence_events WHERE correlation_id = ? ORDER BY sequence ASC"
      )
      .all(correlationId) as {
        sequence: number;
        event_json: string;
        content_hash: string | null;
        prev_hash: string | null;
      }[];

    let verifiedCount = 0;
    let unverifiedCount = 0;
    let expectedPrev: string | null = null;
    let firstBroken: number | null = null;

    for (const row of rows) {
      if (row.content_hash == null) {
        unverifiedCount++;
        continue;
      }
      let eventDict: JsonObject;
      try {
        eventDict = JSON.parse(row.event_json);
      } catch {
        if (firstBroken == null) firstBroken = row.sequence;
        continue;
      }
      const recomputed = computeEventHash(eventDict, row.prev_hash);
      if (recomputed !== row.content_hash || row.prev_hash !== expectedPrev) {
        if (firstBroken == null) firstBroken = row.sequence;
      } else {
        verifiedCount++;
      }
      expectedPrev = row.content_hash;
    }

    return {
      correlation_id: correlationId,
      event_count: rows.length,
      verified_count: verifiedCount,
      unverified_count: unverifiedCount,
      valid: firstBroken == null,
      first_broken_sequence: firstBroken,
    };
  }

  countByCorrelation(correlationId: string): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS count FROM evidence_events WHERE correlation_id = ?")
      .get(correlationId) as { count: number };
    return row.count;
  }

  count(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS count FROM evidence_events")
      .get() as { count: number };
    return row.count;
  }

  listCorrelations(limit = 50): string[] {
    const rows = this.db
      .prepare(
        "SELECT DISTINCT correlation_id FROM evidence_events ORDER BY sequence DESC LIMIT ?"
      )
      .all(limit) as { correlation_id: string }[];
    return rows.map((r) => r.correlation_id);
  }

  close(): void {
    this.db.close();
  }
}

function eventToJson(event: EvidenceEvent): JsonObject {
  return {
    event_id: event.event_id,
    event_type: event.event_type,
    invocation_id: event.invocation_id,
    capability_id: event.capability_id,
    capability_version: event.capability_version ?? null,
    host_id: event.host_id,
    correlation: event.correlation as JsonObject,
    timestamp: event.timestamp,
    sequence: event.sequence,
    outcome: event.outcome ?? null,
    payload: event.payload,
    redacted: event.redacted,
    error: event.error ?? null,
    denial: event.denial ?? null,
    assurance: event.assurance,
  };
}

export { utcNow };
