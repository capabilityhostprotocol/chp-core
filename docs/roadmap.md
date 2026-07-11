# CHP Roadmap

> CHP makes capability execution visible, replayable, and provable — a single
> signed, governed evidence plane for agent work.

## Shipped

**v0.1 — Local Execution Evidence**
Protocol spec, JSON schemas, Python reference host (`chp-core`), TypeScript
types, append-only SQLite evidence store, replay by correlation ID,
conformance suite. Local visibility is free.

**v0.1 Adapter Tier — Governed Adapters**
The `chp-adapter-*` library: HTTP, filesystem, git, GitHub, Radicle, audit,
secrets, CI, conformance, safety, planning, delegation, composition, jobs,
inference (HuggingFace/TEI/vLLM/SGLang/MLX), and more. Every adapter wraps
its operations in evidence.

**v0.2 — Evidence Integrity (spec v0.2.0 → v0.2.7, eight shipped proposals)**
Everything below is conformance-asserted: the black-box wire suite runs
**22 checks against two independent implementations** (Python + TypeScript),
plus an 8-check mesh suite for routing gateways.

- **Signed evidence** (§3): `chp-stable-v1` canonicalization, ed25519 signed
  bundles, graduated assurance tiers, anchored identity (domain +
  Radicle-DID), chained key rotation and revocation.
- **Cross-host verification** (§8): task bundles with causal closure —
  federated `/verify` and `/export` across a mesh.
- **Supply chain** (§9, proposal 0001): publisher-signed adapter provenance
  with an install-time gate.
- **Delegated authority** (§10, proposals 0002/0004/0007): signed, expiring,
  capability-scoped **mandates**; forwarded unchanged through intermediaries;
  **revocable before expiry** (issuer-only rule, `/revocations` distribution).
- **Governed reachability** (§11, proposal 0003): routing is evidence —
  `host_unreachable` denials, transition-gated health events, replayable
  failovers.
- **Mesh witnessing** (§12, proposal 0005): peers countersign each other's
  store heads — evidence becomes tamper-proof *against the host's own
  operator*, with lawful retention distinguishable from rewriting.
- **Governed streaming** (proposal 0006): SSE invocations run the full gate
  pipeline first; denials never commit to a stream.
- **Idempotent replay** (§13, proposal 0008): a host never re-executes a
  recorded `invocation_id` — retries and failover are provably safe.

**Production posture (0.15–0.16)**
Multi-writer-safe store with hot backup (`chp store backup --verify`),
SIGTERM draining, structured error surfacing, fail-loud auth
(`CHP_HOST_REQUIRE_AUTH`), non-root health-checked containers, scheduled
retention, keep-alive client, circuit breaker, and operator metrics — see
[production-runbook.md](production-runbook.md) and [SECURITY.md](../SECURITY.md).

## Active

- **Path to 1.0** — the spec has been additive through eight proposals; the
  remaining work is stability evidence, not features: a published
  compatibility statement, a spec-freeze window with no needed changes, and
  feedback from implementers we don't operate ourselves.
- **Making the proofs visible** — the documentation and examples lag the
  protocol: witnessing, revocation, streaming, and replay deserve worked,
  reproducible demonstrations.

## Next — the planned protocol track

Every change still goes through [spec/proposals/](../spec/proposals/) with
its conformance check, both reference implementations, and byte-identical
published vectors. The planned sequence completes the protocol's remaining
half-finished dimensions:

- **Sub-delegation** — attenuation-only mandate chains (authority that can
  only narrow), verified offline link-by-link
- **Revocation freshness** — bind the revocation-set digest into witnessed
  store heads, making "denial of revocation" detectable
- **Selective disclosure** — redact payloads from a bundle while it still
  verifies against the same signed root
- **Streaming completion** — resumable streams and streaming replay
- **Witness quorum + external anchoring** — k-of-n countersignatures,
  transparency-log anchoring
- **Gateway exactly-once** — cross-owner invocation dedupe
- **1.0 readiness** — `chp-jcs-v1` (RFC 8785), wire-version negotiation,
  compatibility statement, spec freeze

## Guiding Rules

1. **Local visibility is free; production trust is the product.**
2. **Everything additive** — a v0.1-only host stays conformant; published
   test vectors never change bytes.
3. **Every wire-visible change grows the conformance suite** — a feature
   exists when both implementations prove it black-box.
