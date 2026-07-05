/**
 * HTTP binding server (spec/chp-http-binding.md). node:http only. The load-bearing
 * rule: a processed invocation — success/failure/denied/skipped — returns 200 with
 * the InvocationResult in the body; only bad-JSON (400), bad/missing auth (401),
 * and unknown route (404) escape as non-2xx.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
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

export function createHostServer(host: LocalCapabilityHost, opts: { apiKey?: string } = {}): Server {
  const { apiKey } = opts;

  const authed = (req: IncomingMessage): boolean => {
    if (!apiKey) return true;
    const presented = (req.headers['x-chp-key'] as string) ?? '';
    return constantTimeEqual(presented, apiKey);
  };

  return createServer((req, res) => {
    void handle(req, res).catch((e) => err(res, 500, 'internal_error', String((e as Error).message)));
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://x');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // Public: /health (= /)
    if (method === 'GET' && (path === '/' || path === '/health')) {
      const d = host.discover();
      return sendJson(res, 200, {
        status: 'ok', host_id: d.id, protocol: 'chp', version: '0.1', host_version: HOST_VERSION,
      });
    }

    if (!authed(req)) return err(res, 401, 'unauthorized', 'Missing or invalid X-CHP-Key');

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
      const result = await host.ainvokeEnvelope(env);
      return sendJson(res, 200, result as unknown as JsonValue);
    }

    return err(res, 404, 'not_found', `Unknown route: ${path}`);
  }
}
