# CHP Adoption — Capability Host Protocol

Status: legacy. This document describes pre-v0.1 TypeScript adoption paths that are no longer in use.

Start here instead:
- `README.md` — protocol overview and quick start
- `docs/adopter-quickstart.md` — 10-minute path to first evidence event
- `spec/chp-v0.1.md` — normative protocol specification
- `AGENTS.md` — orientation for AI agents working in this repo

CHP lets you expose your project's operations as governed, evidence-emitting capabilities. Any function you wrap gets automatic entitlement checks, risk classification, and evidence trails.

## Get started in 30 seconds

```bash
npx @auxo/chp-init
npm install @auxo/capability-serve
npx tsx src/chp/capabilities.ts
```

`chp-init` detects your project language (TS/Python/Rust), scaffolds `src/chp/` with an example capability, and updates CLAUDE.md.

## Simplest possible CHP adoption

```typescript
import { defineCapability, invoke } from '@auxo/capability-serve';

defineCapability(
  { name: 'myproject.health', version: '1.0.0', risk_class: 'low' },
  async (_ctx, _payload) => ({ success: true, data: { status: 'healthy' } })
);

const result = await invoke('myproject.health:1.0.0', {});
// result.evidence contains execution_started + execution_completed
```

No serve(). No Zenoh. No infrastructure. Just `defineCapability()` + `invoke()`.

## Three tiers

- **Tier 0 (direct):** `defineCapability()` + `invoke()` — governance + evidence, zero infra
- **Tier 1 (governed):** Add `require_entitlement: true`, `risk_class: 'high'`, `enforcement_mode: 'enforce'`
- **Tier 2 (mesh):** Add `serve()` to join Zenoh network for cross-project discovery

## Resources

- Onboarding guide: `docs/onboarding.md`
- Quickstart (v0.1 public): `docs/quickstart.md`
- Spec: `spec/chp-v0.1.md`

## Acceptance criteria

- [ ] 2+ capabilities defined with risk classifications
- [ ] invoke() working with evidence returned
- [ ] 1 test passing
- [ ] Evidence emission for state-changing operations
