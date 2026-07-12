/**
 * HTTP binding server (spec/chp-http-binding.md). node:http only. The load-bearing
 * rule: a processed invocation — success/failure/denied/skipped — returns 200 with
 * the InvocationResult in the body; only bad-JSON (400), bad/missing auth (401),
 * and unknown route (404) escape as non-2xx.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { verifyChainWitness, verifyStoreHeadAnchor, verifyMandateRevocation, computeRevocationHead, PROTOCOL_VERSION, CHP_STORE_HEAD_V2, storeHeadInclusionProof, storeHeadConsistencyProof } from '@capabilityhostprotocol/sdk';
import type { LocalCapabilityHost } from './host.js';
import type { InvocationEnvelope, JsonValue } from './types.js';

const HOST_VERSION = '0.1.0-alpha.0';

function sendJson(res: ServerResponse, status: number, body: JsonValue): void {
  // sorted-key JSON output (chp-http-binding §3)
  const sorted = JSON.stringify(sortKeys(body));
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(sorted) });
  res.end(sorted);
}

function sortKeys(v: JsonValue): JsonValue {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const o: Record<string, JsonValue> = {};
    for (const k of Object.keys(v).sort()) o[k] = sortKeys((v as Record<string, JsonValue>)[k]);
    return o;
  }
  return v;
}

const err = (res: ServerResponse, status: number, code: string, message: string): void =>
  sendJson(res, status, { error: { code, message } });

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

export function createHostServer(
  host: LocalCapabilityHost,
  opts: { apiKey?: string; namedKeys?: string } = {},
): Server {
  const { apiKey } = opts;
  // Received chain-witness statements (§12) — in-memory for the conformance host.
  const receivedWitnesses: Record<string, JsonValue>[] = [];
  const receivedAnchors: Record<string, JsonValue>[] = [];  // §12 External anchoring (0013)
  // chp-revocation-head-v1 (§12, proposal 0010) over the host's held mandate
  // revocations (in-memory conformance host has no key revocations).
  const revocationHead = (): string => computeRevocationHead(
    host.mandateRevocations.map((r) =>
      `m\x00${String(r.mandate_id ?? '')}\x00${String((r.principal as Record<string, JsonValue> | undefined)?.public_key ?? '')}`));
  // Named per-caller keys (binding §2): "name:key[:scope1|scope2],…" — same
  // name may repeat (rotation overlap); a scoped key's out-of-scope invoke is
  // a PROCESSED policy_blocked denial, never a transport 403.
  const named = (opts.namedKeys ?? process.env.CHP_HOST_API_KEYS ?? '')
    .split(',')
    .map((e) => e.split(':', 3))
    .filter((p) => p.length >= 2)
    .map(([name, key, scope]) => ({
      name: name.trim(),
      key: key.trim(),
      scope: scope?.trim() ? scope.split('|').map((s) => s.trim()).filter(Boolean) : null,
    }));

  interface Caller { name: string; scope: string[] | null }

  const authenticate = (req: IncomingMessage): { ok: boolean; caller: Caller | null } => {
    const presented = (req.headers['x-chp-key'] as string) ?? '';
    for (const entry of named) {
      if (constantTimeEqual(presented, entry.key)) {
        return { ok: true, caller: { name: entry.name, scope: entry.scope } };
      }
    }
    if (apiKey) return { ok: constantTimeEqual(presented, apiKey), caller: null };
    return { ok: named.length === 0, caller: null };
  };

  const scopeAllows = (scope: string[], capabilityId: string): boolean =>
    scope.some((s) => capabilityId === s || (s.endsWith('*') && capabilityId.startsWith(s.slice(0, -1))));

  return createServer((req, res) => {
    void handle(req, res).catch((e) => err(res, 500, 'internal_error', String((e as Error).message)));
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://x');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // Version negotiation (spec §1.1, binding §2): an explicit X-CHP-Version not
    // in supported_versions is a transport-level 400 version_unsupported —
    // reject rather than silently process. Absent → today's behavior.
    const requestedVersion = req.headers['x-chp-version'] as string | undefined;
    if (requestedVersion) {
      const supported = (host.discover().supported_versions as string[]) ?? [PROTOCOL_VERSION];
      if (!supported.includes(requestedVersion)) {
        return sendJson(res, 400, {
          error: { code: 'version_unsupported', message: `wire version '${requestedVersion}' not supported; host speaks ${JSON.stringify(supported)}` },
          denial: { code: 'version_unsupported', requested: requestedVersion, supported },
        });
      }
    }

    // Public: /health (= /)
    if (method === 'GET' && (path === '/' || path === '/health')) {
      const d = host.discover();
      return sendJson(res, 200, {
        status: 'ok', host_id: d.id, protocol: 'chp',
        version: String(d.protocol_version ?? PROTOCOL_VERSION), host_version: HOST_VERSION,
      });
    }
    // Public: the identity document — a never-met verifier resolves the key
    // without credentials (spec §3 Anchors); capabilities stay behind auth.
    if (method === 'GET' && path === '/.well-known/chp-identity') {
      return sendJson(res, 200, host.identityDoc());
    }

    const auth = authenticate(req);
    if (!auth.ok) return err(res, 401, 'unauthorized', 'Missing or invalid X-CHP-Key');

    if (method === 'GET' && path === '/host') {
      return sendJson(res, 200, { ...host.discover(), host_version: HOST_VERSION });
    }
    if (method === 'GET' && path === '/capabilities') {
      return sendJson(res, 200, { capabilities: (host.discover().capabilities as JsonValue) });
    }
    if (method === 'GET' && path.startsWith('/replay/')) {
      const corr = decodeURIComponent(path.slice('/replay/'.length));
      return sendJson(res, 200, { correlation_id: corr, events: host.replay(corr) as unknown as JsonValue });
    }
    if (method === 'GET' && path.startsWith('/verify/')) {
      const corr = decodeURIComponent(path.slice('/verify/'.length));
      return sendJson(res, 200, host.verify(corr));
    }
    // Signed-tier export (v0.2): a signed bundle for a correlation, offline-verifiable.
    if (method === 'GET' && path.startsWith('/export/')) {
      const corr = decodeURIComponent(path.slice('/export/'.length));
      return sendJson(res, 200, host.exportBundle(corr));
    }
    if (method === 'GET' && path === '/metrics') {
      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
      return void res.end('# chp ts host metrics (stub)\n');
    }
    // Witnessing (spec §12): the store head a peer countersigns (authed —
    // the sequence discloses activity volume), and this host's received
    // countersignatures (statements only; receipts stay in memory here —
    // a conformance host does not persist).
    if (method === 'GET' && path.startsWith('/head/inclusion/')) {
      // Merkle inclusion (§12, proposal 0019): a chp-store-head-v2 inclusion
      // proof for one correlation under the current head — third-party, no leaves.
      const corr = decodeURIComponent(path.slice('/head/inclusion/'.length));
      const head = host.store.getStoreHead(undefined, CHP_STORE_HEAD_V2);
      if (!(corr in head.leaves)) return err(res, 404, 'not_found', `no correlation ${corr}`);
      return sendJson(res, 200, {
        sequence: head.sequence, store_head: head.store_head,
        proof: storeHeadInclusionProof(head.leaves, corr) as unknown as JsonValue,
      });
    }
    if (method === 'GET' && path === '/head/consistency') {
      // Remote monitor (§12, proposal 0024): a consistency proof between two
      // reconstructed heads so a monitor holding only the anchors verifies
      // append-only with no store copy.
      const first = Number(url.searchParams.get('first'));
      const second = Number(url.searchParams.get('second'));
      if (!Number.isInteger(first) || !Number.isInteger(second) || first > second) {
        return err(res, 400, 'bad_request', 'first and second must be integer sequences, first <= second');
      }
      const oldHead = host.store.getStoreHead(first, CHP_STORE_HEAD_V2);
      const newHead = host.store.getStoreHead(second, CHP_STORE_HEAD_V2);
      return sendJson(res, 200,
        storeHeadConsistencyProof(oldHead.leaves, newHead.leaves) as unknown as JsonValue);
    }
    if (method === 'GET' && path === '/head') {
      const scheme = url.searchParams.get('scheme') ?? undefined;
      const head = host.store.getStoreHead(undefined, scheme);
      return sendJson(res, 200, {
        host_id: host.hostId, scheme: head.scheme, sequence: head.sequence,
        store_head: head.store_head,
        // Revocation freshness (§12, proposal 0010): the held revocation set's digest.
        revocation_head: revocationHead(),
        at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
      });
    }
    if (method === 'GET' && path === '/witnesses') {
      return sendJson(res, 200, { witnesses: receivedWitnesses as unknown as JsonValue });
    }
    if (method === 'POST' && path === '/witness') {
      let stmt: Record<string, JsonValue>;
      try {
        stmt = JSON.parse((await readBody(req)) || '{}') as Record<string, JsonValue>;
      } catch (e) {
        return err(res, 400, 'invalid_json', String((e as Error).message));
      }
      const sv = verifyChainWitness(stmt, { expectedHostId: host.hostId });
      if (!sv.valid) {
        return err(res, 400, 'invalid_witness', sv.reason ?? 'witness statement failed verification');
      }
      const mine = host.store.getStoreHead(Number(stmt.sequence));
      if (mine.store_head !== stmt.store_head) {
        return err(res, 409, 'head_mismatch',
          'statement head does not match this store at that sequence');
      }
      // Revocation freshness (§12, proposal 0010): a statement carrying a
      // revocation_head must match this host's current one.
      if (stmt.revocation_head && stmt.revocation_head !== revocationHead()) {
        return err(res, 409, 'revocation_head_mismatch',
          'statement revocation_head does not match this host\'s current set');
      }
      receivedWitnesses.push(stmt);
      return sendJson(res, 200, {
        accepted: true, sequence: stmt.sequence,
        witness: ((stmt.witness as Record<string, JsonValue> | undefined) ?? {}).host_id ?? null,
      });
    }
    // External store-head anchors (§12 External anchoring, proposal 0013).
    if (method === 'GET' && path === '/anchors') {
      return sendJson(res, 200, { anchors: receivedAnchors as unknown as JsonValue });
    }
    if (method === 'POST' && path === '/anchors') {
      let stmt: Record<string, JsonValue>;
      try {
        stmt = JSON.parse((await readBody(req)) || '{}') as Record<string, JsonValue>;
      } catch (e) {
        return err(res, 400, 'invalid_json', String((e as Error).message));
      }
      if (stmt.host_id !== host.hostId) {
        return err(res, 400, 'invalid_anchor', 'anchor host_id does not match this host');
      }
      const av = verifyStoreHeadAnchor(stmt);
      if (!av.valid) return err(res, 400, 'invalid_anchor', 'anchor failed verification');
      const mine = host.store.getStoreHead(Number(stmt.sequence));
      if (mine.store_head !== stmt.store_head) {
        return err(res, 409, 'head_mismatch', 'anchor head does not match this store at that sequence');
      }
      receivedAnchors.push(stmt);
      return sendJson(res, 200, {
        accepted: true, sequence: stmt.sequence,
        anchor_did: ((stmt.anchor as Record<string, JsonValue> | undefined) ?? {}).did ?? null,
      });
    }

    // Revocation distribution (spec §10 Revocation): serve the held set;
    // accept statements only after self-consistent verification. Whether a
    // statement revokes a GIVEN mandate is gate 5's issuer-only key match.
    if (method === 'GET' && path === '/revocations') {
      return sendJson(res, 200, {
        keys: [], mandates: host.mandateRevocations as unknown as JsonValue,
      });
    }
    if (method === 'POST' && path === '/revocations') {
      let stmt: Record<string, JsonValue>;
      try {
        stmt = JSON.parse((await readBody(req)) || '{}') as Record<string, JsonValue>;
      } catch (e) {
        return err(res, 400, 'invalid_json', String((e as Error).message));
      }
      const rv = verifyMandateRevocation(stmt);
      if (!rv.valid) {
        return err(res, 400, 'invalid_revocation', rv.reason ?? 'revocation statement failed verification');
      }
      const dupe = host.mandateRevocations.some((r) =>
        r.mandate_id === stmt.mandate_id
        && ((r.principal as Record<string, JsonValue> | undefined) ?? {}).public_key
          === ((stmt.principal as Record<string, JsonValue> | undefined) ?? {}).public_key);
      if (!dupe) host.mandateRevocations.push(stmt);
      return sendJson(res, 200, {
        accepted: true, mandate_id: stmt.mandate_id ?? null,
        principal: ((stmt.principal as Record<string, JsonValue> | undefined) ?? {}).host_id ?? null,
      });
    }

    if (method === 'POST' && (path === '/invoke' || path === '/replay')) {
      let body: Record<string, JsonValue>;
      try {
        body = JSON.parse((await readBody(req)) || '{}') as Record<string, JsonValue>;
      } catch (e) {
        return err(res, 400, 'invalid_json', String((e as Error).message));
      }
      if (path === '/replay') {
        const corr = String(body.correlation_id ?? '');
        return sendJson(res, 200, { correlation_id: corr, events: host.replay(corr) as unknown as JsonValue });
      }
      // /invoke — lift top-level correlation_id, always 200 (outcome in body)
      const env = { ...body } as unknown as InvocationEnvelope & { correlation_id?: string };
      if (env.correlation_id && !env.correlation) {
        env.correlation = { correlation_id: env.correlation_id };
        delete env.correlation_id;
      }
      // Verified caller REPLACES any client-asserted subject (binding §2).
      if (auth.caller) {
        env.subject = { id: auth.caller.name, type: 'api_key', verified: true };
        // Capability scope: out-of-scope is a PROCESSED policy_blocked denial.
        if (auth.caller.scope && !scopeAllows(auth.caller.scope, String(env.capability_id ?? ''))) {
          const result = host.denyEnvelope(env, {
            code: 'policy_blocked',
            message: `capability ${String(env.capability_id)} is outside caller ${auth.caller.name}'s key scope`,
            retryable: false,
          });
          return sendJson(res, 200, result as unknown as JsonValue);
        }
      }
      // Streaming (proposal 0006): gates run FIRST via the shared pipeline.
      // JSON-vs-SSE is decided on the FIRST generator item — a denial (or any
      // pre-chunk outcome) answers plain JSON and NEVER commits to SSE; the
      // client switches on Content-Type.
      if (env.mode === 'stream') {
        let committed = false;
        // Resumable streams (§13.1): a reconnect carries the last chunk id seen;
        // resume from the next chunk off the recorded buffer. On client drop keep
        // draining the generator so it records the FULL stream (→ resumable).
        let clientGone = false;
        res.on('close', () => { clientGone = true; });
        const parsed = Number.parseInt(String(req.headers['last-event-id'] ?? ''), 10);
        const resumeFrom = Number.isFinite(parsed) ? parsed : -1;
        let nextId = resumeFrom + 1;
        const sse = (event: string, data: JsonValue, eid?: number): void => {
          if (clientGone) return;
          const idLine = eid !== undefined ? `id: ${eid}\n` : '';
          res.write(`${idLine}event: ${event}\ndata: ${JSON.stringify(sortKeys(data))}\n\n`);
        };
        for await (const item of host.ainvokeStream(env, resumeFrom)) {
          if ('result' in item && !committed) {
            return sendJson(res, 200, item.result as unknown as JsonValue);
          }
          if (!committed) {
            committed = true;
            req.socket.setTimeout(600_000); // real streams outlive the default
            res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
          }
          if ('result' in item) sse('result', item.result as unknown as JsonValue, nextId);
          else { sse('chunk', { delta: item.chunk }, nextId); nextId += 1; }
        }
        return void res.end();
      }
      const result = await host.ainvokeEnvelope(env);
      return sendJson(res, 200, result as unknown as JsonValue);
    }

    return err(res, 404, 'not_found', `Unknown route: ${path}`);
  }
}
