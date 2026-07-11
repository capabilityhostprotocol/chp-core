# Security Policy

## Reporting a vulnerability

Email **security@capabilityhostprotocol.com** with a description, reproduction
steps, and the affected version. Please do not open a public issue for
undisclosed vulnerabilities. We aim to acknowledge reports within 72 hours.

Signed evidence, identity, provenance, mandate, and witnessing verification
are the protocol's security core — reports against
`packages/python/chp_core/signing.py`, the canonicalization
(`chp-stable-v1`), or the conformance suite's guarantees are especially
valuable.

## Supported versions

| Version | Supported |
|---|---|
| 0.15.x | ✅ |
| 0.14.x | ✅ (security fixes) |
| < 0.14 | ❌ — upgrade (`chp-host update`) |

All protocol changes are additive (spec/CHANGELOG.md documents every
version's regression gate), so upgrading within the 0.x line does not break
wire compatibility.

## Threat model & hardening

- Threat model: [docs/security/threat-model-v0.1.md](docs/security/threat-model-v0.1.md)
- Production hardening & operations: [docs/production-runbook.md](docs/production-runbook.md)
- Key compromise recovery: rotation (spec §3.2) → key revocation → re-anchor
  → mandate revocation (spec §10) — the runbook has the step-by-step.
