import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { buildFixtureHost } from '../src/fixtures.js';
import { createHostServer } from '../src/server.js';

// TS parity for the chp-server surface (/ready + /server) — the provably-a-protocol
// discipline: a host-profile server must describe itself with the SAME shape + feature
// truth on both implementations. Ground truth is the Python chp_server.describe() /
// ready() for `profile="host"` (see IMPLEMENTATION_STATUS deployment-proof section).
let server: Server;
let base: string;

beforeAll(async () => {
  server = createHostServer(buildFixtureHost());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => server.close());

describe('chp-server surface parity — /ready + /server', () => {
  it('/ready is public and reports a ready host-profile server', async () => {
    const res = await fetch(`${base}/ready`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      ready: true, state: 'ready', profile: 'host', missing_required_roles: [],
    });
  });

  it('/server describes the host-profile server with the Python-parity key set', async () => {
    const res = await fetch(`${base}/server`);
    expect(res.status).toBe(200);
    const d = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(d).sort()).toEqual([
      'attachments', 'config', 'config_generation', 'core_version', 'distribution_version',
      'environment', 'features', 'instance', 'lifecycle_state', 'profile', 'profiles_available',
      'protocol_version', 'server', 'supported_versions',
    ]);
    expect(d.profile).toBe('host');
    expect(d.lifecycle_state).toBe('ready');
    expect((d.instance as { id: string }).id).toMatch(/[0-9a-f-]{36}/);
  });

  it('/server feature truth matches the Python host-profile projection exactly', async () => {
    const d = (await (await fetch(`${base}/server`)).json()) as {
      features: Array<{ feature: string; state: string }>;
    };
    const states = Object.fromEntries(d.features.map((f) => [f.feature, f.state]));
    // identical to chp_server describe() for profile="host"
    expect(states).toEqual({
      'capability.discovery': 'ready',
      'capability.resolve': 'unsupported',
      'invocation.submit': 'ready',
      'invocation.local': 'ready',
      'invocation.observe': 'ready',
      'invocation.streaming': 'ready',
      'invocation.remote': 'unsupported',
      'evidence.query': 'ready',
      'evidence.verify': 'ready',
      'artifact.transfer': 'unsupported',
      'federation': 'unsupported',
      'mcp.import': 'unsupported',
      'mcp.export': 'unsupported',
    });
  });
});
