import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { orderEvents } from '../src/ordering.js';
import type { EvidenceEvent } from '../src/hash.js';

const vec = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../../spec/test-vectors/ordering.json', import.meta.url)), 'utf8',
)) as { events: EvidenceEvent[]; expected_order: string[] };

describe('chp-causal-order-v1 (cross-language determinism)', () => {
  it('reproduces the published vector exactly', () => {
    expect(orderEvents(vec.events).map((e) => e.event_id)).toEqual(vec.expected_order);
  });

  it('input order is irrelevant', () => {
    expect(orderEvents([...vec.events].reverse()).map((e) => e.event_id)).toEqual(vec.expected_order);
  });

  it('causal edge overrides wall clock (skewed host-B)', () => {
    const order = orderEvents(vec.events).map((e) => e.event_id);
    expect(order.indexOf('evt_a1')).toBeLessThan(order.indexOf('evt_b1'));
  });

  it('byte-wise tiebreak: host-B before host-a at equal timestamps', () => {
    const order = orderEvents(vec.events).map((e) => e.event_id);
    expect(order.indexOf('evt_b3')).toBeLessThan(order.indexOf('evt_a3'));
  });

  it('total on cyclic input', () => {
    const a = { event_id: 'x', invocation_id: 'ix', host_id: 'h1', sequence: 1,
      timestamp: 't1', correlation: { causation_id: 'iy' } } as unknown as EvidenceEvent;
    const b = { event_id: 'y', invocation_id: 'iy', host_id: 'h2', sequence: 1,
      timestamp: 't2', correlation: { causation_id: 'ix' } } as unknown as EvidenceEvent;
    expect(orderEvents([a, b]).map((e) => e.event_id).sort()).toEqual(['x', 'y']);
  });
});
