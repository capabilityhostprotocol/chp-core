/**
 * The conformance fixture profile (conformance/FIXTURES.md). Registers the eight
 * capabilities + host config a `wire`-suite host-under-test must expose.
 */

import { type HostKey } from '@capabilityhostprotocol/sdk';
import { LocalCapabilityHost } from './host.js';
import { RuleBasedSafetyEvaluator } from './safety.js';
import { StreamResult } from './types.js';
import type { Ctx, JsonValue } from './types.js';

export function buildFixtureHost(signingKey?: HostKey, domain?: string): LocalCapabilityHost {
  const evaluator = new RuleBasedSafetyEvaluator([
    {
      id: 'conformance-guardrail',
      capability_id_pattern: 'conformance.unsafe',
      max_risk_level: 'critical',
      requires_human_for: ['conformance.unsafe'],
    },
  ]);
  const host = new LocalCapabilityHost('conformance-host', {
    policy: { max_risk_tier: 'medium' },
    safetyEvaluator: evaluator,
    signingKey,
    domain,
  });

  const echo = async (_c: Ctx, payload: JsonValue) => ({ echo: (payload as { value?: JsonValue }).value ?? null });

  host.register({ id: 'conformance.echo', version: '1.0.0', description: 'Echo a value.' }, echo);
  host.register({ id: 'conformance.fail', version: '1.0.0', description: 'Fail deterministically.' }, async () => {
    throw new Error('expected failure');
  });
  host.register(
    {
      id: 'conformance.guarded', version: '1.0.0', description: 'Require payload.value.',
      invariants: [{ id: 'requires_value', kind: 'required_payload_fields', enforcement: 'host', parameters: { fields: ['value'] }, failure_behavior: 'deny' }],
    },
    echo,
  );
  host.register({ id: 'conformance.approval', version: '1.0.0', description: 'Approval-gated.', autonomy: { tier: 'approval_required' } }, echo);
  host.register({ id: 'conformance.budgeted', version: '1.0.0', description: 'Budget-capped.', autonomy: { action_limit: 1 } }, echo);
  host.register({ id: 'conformance.risky', version: '1.0.0', description: 'High-risk.', risk: 'high' }, echo);
  host.register({ id: 'conformance.unsafe', version: '1.0.0', description: 'Blocked by a safety guardrail.' }, echo);
  host.register(
    { id: 'conformance.stream', version: '1.0.0', description: 'Stream three deterministic chunks.', modes: ['sync', 'stream'] },
    async function* (_c: Ctx, _payload: JsonValue) {
      yield 's1'; yield 's2'; yield 's3';
      yield new StreamResult({ chunks: 3, joined: 's1s2s3' });
    },
  );

  return host;
}
