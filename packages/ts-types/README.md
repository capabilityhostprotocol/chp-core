# @chp/types

TypeScript protocol types for CHP v0.1.

## Overview

CHP v0.1 makes capability execution visible, replayable, and ready for governance. The package root exports only the schema-aligned v0.1 protocol types and mirrors the JSON Schemas in `schemas/`.

The root export is the public v0.1 protocol surface. It does not expose the
older internal mesh/governance model.

## Installation

```bash
npm install @chp/types
# or
pnpm add @chp/types
```

## Usage

```typescript
import type {
  CapabilityDescriptor,
  CorrelationContext,
  ExecutionEvidence,
  HostDescriptor,
  InvocationEnvelope,
  InvocationResult,
  ReplayResult,
} from '@chp/types';
```

```typescript
const correlation: CorrelationContext = {
  correlation_id: 'corr_123',
};

const descriptor: CapabilityDescriptor = {
  id: 'example.search_information',
  version: '0.1.0',
  description: 'Search for information.',
  modes: ['sync'],
  emits: ['execution_started', 'execution_completed', 'execution_failed'],
};
```

Use the schema names for v0.1 integrations:

- `CapabilityDescriptor`
- `HostDescriptor`
- `InvocationEnvelope`
- `InvocationResult`
- `ExecutionEvidence`
- `CorrelationContext`
- `ReplayQuery`
- `ReplayResult`

## Legacy Usage

Older internal mesh/governance helper types are available from the explicit
legacy subpath while internal systems migrate:

```typescript
import {
  createEvidence,
  createGovernedContext,
  createSubjectContext,
  type Evidence,
  type RiskClass,
  type AssuranceTier,
} from '@chp/types/legacy';

// Create a subject
const subject = createSubjectContext({
  subject_id: 'user-123',
  subject_type: 'user',
  entitlements: ['payment.process', 'user.read'],
});

// Create governed context
const ctx = createGovernedContext({
  capability_id: 'payment.process:1.0.0',
  subject,
  governance_mode: 'enforce',
  risk_class: 'high',
  minimum_tier: 'S2',
});

// Emit evidence
const evidence = createEvidence({
  evidence_type: 'execution_completed',
  capability_id: ctx.capability_id,
  subject_id: subject.subject_id,
  correlation_id: ctx.correlation_id,
  assurance_tier: 'S2',
  payload: { amount: 100.00, currency: 'USD' },
});
```

## Type Correspondence

| CHP v0.1 Concept | Python `chp_core` | TypeScript `@chp/types` |
|---|---|---|
| Capability descriptor | `CapabilityDescriptor` | `CapabilityDescriptor` |
| Host descriptor | `HostDescriptor` | `HostDescriptor` |
| Invocation envelope | `InvocationEnvelope` | `InvocationEnvelope` |
| Invocation result | `InvocationResult` | `InvocationResult` |
| Execution evidence | `ExecutionEvidence` | `ExecutionEvidence` |
| Correlation context | `CorrelationContext` | `CorrelationContext` |
| Replay query | `ReplayQuery` | `ReplayQuery` |
| Replay result | `ReplayResult` | `ReplayResult` |

## Verification

```bash
npm run typecheck --workspace @chp/types
npm run build --workspace @chp/types
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
