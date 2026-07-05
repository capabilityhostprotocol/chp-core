#!/usr/bin/env node
/**
 * chp-host-ts serve --port <n> --key <k>
 * Boots the conformance fixture host over HTTP for `conformance/runner.py --url`.
 */

import { generateKeypair } from '@capabilityhostprotocol/sdk';
import { buildFixtureHost } from '../fixtures.js';
import { createHostServer } from '../server.js';

function arg(name: string, def?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}

const port = Number(arg('port', '8899'));
const key = arg('key');
const sign = process.argv.includes('--sign');
const domain = arg('domain'); // domain anchor (spec §3.1) — implies --sign

const server = createHostServer(
  buildFixtureHost(sign || domain ? generateKeypair() : undefined, domain),
  { apiKey: key },
);
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`chp-host-ts listening on http://127.0.0.1:${port}${key ? ' (auth on)' : ''}\n`);
});
