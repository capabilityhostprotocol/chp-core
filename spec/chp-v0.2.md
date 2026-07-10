# Capability Host Protocol — v0.2 (Evidence Integrity)

Status: **released** (v0.2 2026-07-06; v0.2.1–v0.2.4 additions 2026-07-09/10). Changes via [proposals/](proposals/) — see [CHANGELOG.md](CHANGELOG.md). **Additive** over [v0.1](chp-v0.1.md); a v0.1-only host remains
conformant at the `none` assurance tier. v0.2 defines an *optional* tamper-
evident evidence layer without changing the v0.1 local-first experience.

Key words MUST, SHOULD, MAY per RFC 2119.

## 1. Assurance Tiers

A host declares one of three evidence assurance tiers:

- `none` — local append-only evidence (v0.1 baseline).
- `hash-chain` — each event carries `content_hash` + `prev_hash` forming a
  per-store SHA256 chain that detects mutation and reordering.
- `signed` — a `hash-chain` bundle whose root hash is signed with the host's
  ed25519 key, detecting tampering by any party without the private key.

A host MUST declare its tier in the `/host` descriptor as `assurance`. A signed
host MUST additionally expose `key_id` and `public_key`. A verifier MUST reject
a tier lower than the one it requires rather than silently degrading.

## 2. Hash Chain (`hash-chain` and above)

Each evidence event MUST carry:
- `content_hash` — SHA256 over the event's canonicalized stable fields
  (`event_id`, `event_type`, `invocation_id`, `capability_id`, `host_id`,
  `correlation_id`, `timestamp`, `outcome`, `payload`) plus the `prev_hash`.
- `prev_hash` — the `content_hash` of the preceding event in the same chain.

The canonicalization scheme MUST be named. This version defines **`chp-stable-v1`**
**byte-exact** so any implementation — in any language — computes the identical
`content_hash` and can verify a signature produced by another. The stable object is:

```
{event_id, event_type, invocation_id, capability_id, host_id,
 correlation_id, timestamp, outcome, payload, prev_hash}
```

where `correlation_id` is extracted from the event's `correlation` object and
`prev_hash` is a member key (null for the first event). It is serialized with
these exact rules (matching Python `json.dumps(obj, sort_keys=True)`):

1. **Object keys sorted** ascending by Unicode code point, **recursively**.
2. **Separators with spaces**: `", "` between members/items, `": "` between key
   and value. (Object `{"a": 1, "b": 2}`, not compact `{"a":1,"b":2}`.)
3. **ASCII-only strings**: every non-ASCII character is escaped as `\uXXXX`
   (lowercase hex; surrogate pairs for astral code points). `"café"` →
   `"café"`. (This supersedes any earlier "over UTF-8" wording.)
4. Standard JSON escapes for `"` `\` and control chars `\b \t \n \f \r`,
   `\u00XX` for other C0 controls.
5. `null`/`true`/`false` lowercase; integers bare.
6. **No non-integer numbers.** Canonicalized content MUST NOT contain a JSON
   *float*. Float-to-string serialization is not portable — Python `json.dumps`
   emits `0.0` where an ECMAScript `Number.toString` emits `0`, so the same value
   would hash differently across languages. A value that is conceptually
   fractional (e.g. a safety `score`, an autonomy `spend`) MUST be represented in
   canonicalized fields as a **string** (fixed precision, e.g. `"0.000"`) or a
   scaled integer. Producers put the human/float form only in non-hashed surfaces
   (an `InvocationResult.data`, an OTel attribute), never in an evidence event
   payload. (This is the one place `chp-stable-v1` deliberately narrows JSON.)
7. The resulting string is UTF-8-encoded (pure ASCII here) and SHA-256'd →
   lowercase hex `content_hash`.

The **root hash** = SHA-256 over each event's `content_hash`, in sequence order,
each **followed by a `\n`** (`0x0a`) — i.e. `sha256(h1 + "\n" + h2 + "\n" + …)`.
The **signature** (ed25519) is computed over the **ASCII-hex `root_hash` string**
(not the raw digest bytes).

`spec/test-vectors/` publishes fixed inputs → exact `content_hash`, `root_hash`,
and signature (with a fixed key seed), plus `verify.mjs` — a stdlib-only Node
verifier that validates a Python-signed bundle from these rules alone, proving
cross-language interoperability. A future `chp-jcs-v1` (RFC 8785 JCS: compact,
raw-UTF-8) MAY be added non-breakingly via the `canonicalization` field.

Strict verification MUST fail on any event lacking a `content_hash`. Lenient
verification MAY tolerate legacy unhashed events, but MUST NOT be the default
for a host declaring `hash-chain` or `signed`.

## 3. Signed Bundles (`signed`)

A host at the `signed` tier MUST support exporting a correlation as a bundle:

```json
{
  "host_id": "…", "protocol_version": "0.2", "created_at": "…",
  "canonicalization": "chp-stable-v1", "assurance": "signed",
  "events": [ … ], "root_hash": "hex…",
  "public_key": "base64…",
  "host_identity": {
    "host_id": "…", "public_key": "base64…", "key_id": "…",
    "valid_from": "…", "valid_until": null, "signature": "base64…"
  },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "base64…" }
}
```

- `root_hash` MUST be the SHA256 over each event's `content_hash` in sequence
  order. Signing the root (not each event) is REQUIRED.
- **The signature covers the canonical *header***, not just `root_hash`. The
  signed message is `chp-stable-v1(  {host_id, protocol_version, created_at,
  canonicalization, root_hash}  )`. This binds the claimed origin/time/scheme
  into the signature: a relabelled top-level `host_id` (or `created_at`, …)
  MUST fail verification. (Events are bound transitively via `root_hash`.)
- **Host-identity attestation** (`host_identity`): a self-signed statement
  binding `host_id` ↔ `public_key`. `key_id = sha256(pubkey)[:16]` only binds a
  key to *itself* and `host_id` is a free string, so a signed bundle otherwise
  proves *integrity*, not *provenance*. The attestation is
  `chp-stable-v1({host_id, public_key, key_id, valid_from, valid_until})` signed
  by the key. A verifier at the `signed` tier MUST, when `host_identity` is
  present, check that its `host_id`/`public_key` match the bundle and its
  signature verifies under `public_key`. This is the trust *floor* (the key
  self-asserts its host_id — TOFU/`mesh.py:pin_or_check_key` pins it on first
  contact); **Anchors** (§3.1) upgrade the floor by binding the key to an
  external trust root a never-met verifier can resolve.
- A verifier MUST check: per-event hash recompute, chain continuity, root hash,
  the header signature, and (when present) the host-identity attestation. A
  verifier offered an `expected_key_id` MUST reject a bundle signed by any other
  key.

A `signed` host SHOULD also serve its `host_identity` attestation on the `/host`
descriptor, so a mesh peer can verify the key self-attests this `host_id` (and is
within its validity window) **before** trust-on-first-use pinning it — rather than
pinning whatever `/host` self-reports. This is the same offline
`verify_attestation` check the bundle path uses.

Key rotation uses `valid_from`/`valid_until` in the `host_identity` attestation.
A verifier MUST reject a signed bundle whose `created_at` falls outside the
attestation's `[valid_from, valid_until]` window (the key had expired when it
signed) — enforced offline against `created_at`, so no wall clock is required.
`null` bounds are unbounded. Chained rotation and revocation are specified in
§3.2.

### 3.1 Anchors — cross-org trust

An **anchor** binds the signing key to an external trust root a never-met
verifier can resolve, upgrading a bundle from *integrity* (TOFU floor) to
*provenance* ("root R vouches for key P"). Anchors are an OPTIONAL list inside
the **signed attestation claim**:

```json
"host_identity": {
  "host_id": "…", "public_key": "…", "key_id": "…",
  "valid_from": "…", "valid_until": null,
  "anchors": [ {"type": "domain", "domain": "acme.example"} ],
  "signature": "base64…"
}
```

- **Omit-when-empty (byte rule).** The `anchors` key MUST be omitted from the
  claim entirely when there are no anchors — never emitted as `[]` or `null`.
  A no-anchor attestation is thus byte-identical to the pre-anchor format
  (`spec/test-vectors/signed-bundle.json` is the compatibility gate). A verifier
  reconstructs the claim with the same conditional: `anchors` participates in
  the signed bytes exactly when the attestation carries it. Because anchors are
  inside the signed claim, **stripping** one (downgrade) or **stapling** one on
  (forgery) breaks the self-signature. Anchor values MUST NOT contain
  non-integer numbers (§2 rule 6); array order is preserved as built.
- **The anchor is the trust root; `host_id` is a local label.** A verifier MUST
  surface *which root vouched* (e.g. the resolved domain) as the answer to
  "whose?", and MUST NOT treat `host_id` as trusted. An attacker-controlled
  anchor "verifies" — against *the attacker's root*; the trust decision belongs
  to the caller reading the surfaced root.
- **Key custody.** A deployment SHOULD provision a **distinct signing key per
  `host_id`**. Nothing in the format forbids one key attesting several
  host_ids, but shared custody collapses "which host signed this" into "which
  key-holder signed this" — with a machine-wide key, per-host attribution is
  only as strong as the machine boundary. (The reference implementation
  resolves per-host key directories with a shared-key fallback.)
- **`domain` anchor.** Proves: "the entity in administrative control of the
  domain (DNS + TLS certificate + server) asserts key P is its CHP signing
  key" — the Web-PKI chain, the RFC 8615 / MTA-STS pattern. The host MUST serve
  its identity document at `GET /.well-known/chp-identity` **without
  authentication** (`{assurance, key_id, public_key, host_identity}` — key
  material only; capabilities stay behind auth). A resolving verifier MUST
  fetch over `https://` only and MUST NOT follow redirects; it confirms the
  bundle's `public_key` appears in the resolved document. Resolution proves
  *current* control of the anchor; the attestation window proves *validity at
  signing time* — the two are distinct and both recorded. Unknown anchor types
  MUST be skipped (forward compatibility); if resolution was requested and no
  anchor type is understood, the result is *unverifiable provenance*, never
  success. A no-anchor bundle under a resolving verifier remains valid at the
  visibly-TOFU floor.
- **`did` anchor.** Proves: "the holder of the ed25519 identity behind
  `did:key:z6Mk…` countersigned this CHP key" — fully **offline**, no CA/DNS.
  Shape: `{"type": "did", "did": "did:key:z6Mk…", "countersignature": "<armored
  SSHSIG>"}`. The countersignature is an OpenSSH **SSHSIG** (`ssh-keygen -Y
  sign`) with namespace **`chp-host-anchor`** over the message
  `chp-stable-v1({"chp_public_key": <base64 CHP key>, "host_id": <host_id>})`.
  The DID is multibase(base58btc) of multicodec(`0xed01`) + the raw 32-byte
  ed25519 public key (for a Radicle node, byte-identical to `"did:key:" + NID`).
  A verifier MUST decode the DID to the raw key, pin the SSHSIG signer to it,
  and verify the SSHSIG payload (`SSHSIG || namespace || reserved || hash_alg ||
  H(message)`). `spec/test-vectors/did-anchored-bundle.json` is the fixture
  (produced by a real `ssh-keygen -Y sign` with a fixed-seed key). Verification
  is offline and MUST run whenever a `did` anchor is present.
- A host MAY carry multiple anchors so verifiers choose their preferred root;
  further anchor types extend the same list.
- **Stated tradeoff:** the `domain` anchor deliberately leans on Web-PKI
  (CA + DNS) as the buildable, standards-aligned floor-above-TOFU; the `did`
  anchor is the decentralized ceiling that removes that dependency.

### 3.2 Key lifecycle — rotation with continuity, revocation

Rotation MUST NOT destroy the old key (archive it) and MUST NOT be
indistinguishable from impersonation. On rotation the **old** key signs a
self-contained **continuity statement**:

```json
{ "old_key_id": "…", "old_public_key": "…", "new_key_id": "…",
  "new_public_key": "…", "rotated_at": "…", "signature": "<by the OLD key>" }
```

The host publishes its lineage as `key_history` (an ordered list of continuity
statements) on the identity document / `/host`. A verifier holding a pinned key
that encounters a changed key MUST accept it **only** by walking the continuity
chain from its own pinned key — each hop verified under the key trusted *so
far*, starting from the verifier's pin, never from the remote's self-published
`old_public_key` — and re-pin with trust `rotated`. A change with no valid
chain remains a hard mismatch. (The remote's history cannot vouch for itself.)

**Revocation** is a self-signed statement by the revoked key
(`{revoked_key_id, revoked_public_key, revoked_at, reason, signature}`)
published as `revoked_keys` on the identity document. A resolving verifier
(`resolve=True`) MUST reject a bundle signed by a key the resolved document
revokes (`not_revoked` check). **Offline verifiers cannot see revocations** —
a stated limit of this tier; there is no global revocation infrastructure.

**Identity evidence.** The lifecycle is recorded on the host's **own**
hash-chained store via the reserved host-self event family
`IDENTITY_EVIDENCE_TYPES` = {`key_generated`, `key_rotated`, `key_revoked`,
`identity_anchored`} (governance §4.5) under the correlation
`host-identity-<host_id>`. The chain's append-only, tamper-evident ordering
makes it the host's **key-transparency log**, exportable and verifiable like
any evidence bundle. This is the first evidence family that describes the host
itself rather than a capability invocation.

## 4. Retention (all tiers)

Retention MUST NOT break the verifiability of retained evidence. An
implementation MUST prune at whole-correlation granularity (or an equivalent
that never orphans a survivor's `prev_hash`). Payload redaction that rewrites a
stored event MUST clear that event's `content_hash` (rendering it `unverified`)
rather than leave a hash that no longer matches.

## 5. Transport / Auth (informative for v0.2)

HTTP hosts MUST compare authentication credentials in constant time. A host
SHOULD bind an authenticated caller to a verified `subject` on the evidence it
records. Network-layer confidentiality (e.g. a private mesh) MAY substitute for
transport TLS.

## 6. Conformance

v0.2 adds these checks to the runner (gated by declared tier):
`signed evidence bundle`, `strict verify rejects unhashed`,
`retention preserves chain`. A host declaring a tier MUST pass the checks for
that tier and below.

## 7. Cross-host ordering — `chp-causal-order-v1`

A task's evidence may span multiple hosts sharing one `correlation_id` (the
gateway forwards the caller's correlation unchanged). v0.1 §10 left cross-host
ordering undefined; this section defines it. Given the events of ONE
correlation gathered from N hosts, a conforming implementation MUST produce
this total order:

- **Sort key** `K(e) = (timestamp, host_id, sequence, event_id)` — string
  components compared **byte-wise over UTF-8** (case-sensitive; a locale or
  case-folding comparator is non-conforming), missing strings as `""`, missing
  `sequence` as `0`.
- **Happens-before edges:** (1) events with equal `host_id` are ordered by
  `sequence`; (2) an event whose `correlation.causation_id` names invocation
  `C` is ordered after the K-minimal event carrying `invocation_id == C`
  (the *causal spawn* edge), when that event is present in the set.
- **Algorithm:** Kahn's topological sort whose ready set is ordered by K
  (pop-minimum). Because `(host_id, sequence)` is unique per event, K is a
  total order and the output is **deterministic** — independent of input
  order and identical across implementations. On cyclic input (possible only
  with tampered or malformed data) the remainder MUST be emitted in K order;
  the function is total, and cycle *detection* is a verification concern
  (task-bundle verification).

The K tiebreak orders **causally-unrelated** (concurrent) events only; it is
arbitrary-but-deterministic, not a claim about real time — wall clocks skew,
and a causal edge always overrides timestamps (a child spawned cross-host is
ordered after its cause even when the child host's clock reads earlier).
Known limit: only the spawn edge is causal; a synchronous parent's terminal
event is placed by K, not by an edge.

`spec/test-vectors/ordering.json` pins a shuffled 3-host input (with a skewed
clock and a byte-order tiebreak trap) and its exact expected order; both
reference implementations reproduce it (`chp_core/ordering.py`,
`chp-sdk/src/ordering.ts`).

Correlation-context notes: `trace_id` is OPTIONAL/reserved — when present, a
W3C trace-context trace id (the OTel exporter uses it and falls back to
`correlation_id`); `baggage` is reserved for forward compatibility;
`parent_correlation_id` is informative session-threading linking a spawned
task's correlation to its spawning session — it is NOT part of
chp-causal-order-v1, which operates within one `correlation_id`.

**Deferred execution.** When an invocation defers work — a background job, a
queued task, any execution that outlives the submitting request — the deferred
execution MUST propagate the submitting invocation's correlation with a causal
edge (same `correlation_id`, `causation_id` = the submitting `invocation_id`),
exactly as a synchronous child would. Minting a fresh correlation for deferred
work severs the evidence chain from the invocation that was governed at submit
time: the pipeline's gates ran against the submit, so the execution's evidence
MUST remain reachable from it. (The reference `chp.adapters.jobs` adapter is
the canonical example.)

## 8. Task Bundles — cross-host verification

A **task bundle** makes a task spanning N hosts verifiable **as a unit**. It
aggregates one correlation's per-host bundles, byte-untouched:

```json
{
  "kind": "task-bundle",
  "correlation_id": "…", "created_at": "…",
  "protocol_version": "0.2", "canonicalization": "chp-stable-v1",
  "assurance": "signed",
  "bundles": [ { …signed per-host bundle… }, … ],
  "task_root_hash": "hex64"
}
```

- **Members are byte-untouched** signed bundles (§3) — their signatures remain
  independently verifiable. Members MUST be sorted by `(host_id, root_hash)`,
  byte-wise, so assembly order is irrelevant: two aggregators assembling the
  same members produce identical bytes.
- **`task_root_hash`** = SHA-256 over each member's `root_hash` in array order,
  each followed by `\n` — the §2 root-hash pattern one level up. It is the
  task's single tamper-evident fingerprint: swapping, adding, or dropping any
  member changes it.
- **`assurance`** MUST be the MINIMUM member tier — degradation is surfaced,
  never hidden. Member signatures prove each part's origin; the OPTIONAL
  `aggregator` layer below additionally proves who assembled the set.

**Aggregator signature (the `aggregated` layer, optional).** The assembling
host MAY sign the assembly: an `aggregator` object carrying its `host_id`,
`public_key`, its own `host_identity` attestation (§3, anchors included when
anchored), and a `signature` over the canonical **task header**
`{kind, correlation_id, protocol_version, created_at, canonicalization,
task_root_hash}`. Because `task_root_hash` commits to every member root and
member order is canonical, signing the header signs the assembly: re-assembling
the set (adding, dropping, or swapping members) breaks the aggregator
signature even if the attacker recomputes `task_root_hash`. **Omit-when-empty**:
an unsigned task bundle is byte-identical to the pre-aggregator format — every
published vector is unchanged. A verifier MUST verify the aggregator whenever
present and MUST surface its absence (`aggregator: null`) rather than treat
unsigned assembly as verified assembly. Vector:
`test-vectors/task-bundle-aggregated.json`.

**Participation manifest (optional).** An orchestrating host MAY declare the
member set by emitting the reserved `task_participants_declared` event
(payload: `{"participants": [host_id, …]}`, sorted) under the task's
correlation — on its OWN signed chain, so the declaration inherits the
declarer's signature and anchors. When any member's events include such a
declaration, verification MUST check that **every declared `host_id` has a
member bundle** (declarations union across events). This closes the leaf-
omission gap below for declared sets: omitting a declared member now dangles
against a signed expectation.

**Verification** (all MUST pass): structure; canonical member order;
`task_root_hash` recompute; every member verifies fully under §3 (chain, root,
header signature, attestation, anchors); every event carries the task's
`correlation_id`; member `host_id`s are pairwise distinct; **causal closure** —
every non-null `causation_id` in any member resolves to an `invocation_id`
present in the union of members (no dangling causal references); the
chp-causal-order-v1 edge set over the union is **acyclic**; **participation**
when a manifest is declared (above); and the **aggregator** signature when
present (above). The verifier MUST surface per-member identity (host_id,
key_id, assurance, anchors) — who contributed what, under which trust root.

**Completeness limit (normative):** task-bundle verification proves the
integrity of every included part, the cryptographic identity of every
contributor, and causal closure. It does NOT prove the absence of evidence: a
causal *ancestor* cannot be silently dropped (its children's `causation_id`s
would dangle), and a **declared** member cannot be omitted (the participation
check), but an *undeclared leaf* contributor — a host whose invocations
nothing else references and no manifest names — can still be omitted
undetectably. Absence-proofs beyond declared sets are out of scope.

`spec/test-vectors/task-bundle.json` is the fixture (two fixed-seed hosts with
cross-host causation); `verify.mjs` verifies it from these rules alone.

## 9. Supply Chain — Adapter Provenance

Evidence is signed, task assemblies are signed, identities anchor to external
roots — this section closes the remaining unsigned link: the **adapter code
that produces the evidence**. An **adapter-provenance statement** is a
publisher's signed claim that they built an exact artifact:

```json
{
  "kind": "adapter-provenance",
  "package": "chp-adapter-http", "version": "0.10.0",
  "wheel_sha256": "hex64",
  "created_at": "…", "canonicalization": "chp-stable-v1",
  "publisher": {
    "host_id": "…", "public_key": "base64…",
    "host_identity": { …attestation, anchors ride inside (§3.1)… }
  },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "base64…" }
}
```

- **The signature covers the canonical header** `{kind, package, version,
  wheel_sha256, created_at, canonicalization}` — relabelling the package,
  version, or artifact hash breaks it.
- **`wheel_sha256` is the SHA-256 of the artifact file** — checkable *before
  anything executes*. The installed-files fingerprint (`record_sha256`) is
  deliberately NOT in the signed statement: installers rewrite `RECORD` at
  install time, so it is not a pre-install invariant; it remains the
  evidence-side fingerprint in `host_adapter_installed`.
- **The publisher is a host identity** (§3): the attestation binds
  `host_id ↔ public_key`, and anchors (§3.1) answer "whose?" through the same
  roots as evidence bundles. No separate publisher PKI.

**Verification** (all MUST pass): structure; header signature; publisher
attestation (binding + temporal validity at `created_at`); the DID anchor when
present; and — when the verifier holds the artifact — `wheel_sha256` equality.
Vector: `test-vectors/adapter-provenance.json` (verified by both reference
implementations and `verify.mjs`). Ecosystem interop (sigstore, SLSA,
PEP 740): [docs/security/provenance-interop.md](../docs/security/provenance-interop.md).

**Install-time gate.** An installer operating in required-provenance mode MUST
obtain the artifact *without executing it*, hash it, verify the statement, and
refuse on any failure — recording the refusal as the reserved
`host_adapter_install_rejected` event (a refusal is evidence, like a denial).
A verified install SHOULD embed the statement in its `host_adapter_installed`
evidence, upgrading the record from self-reported to publisher-signed. Both
events are reserved (`SUPPLY_CHAIN_EVIDENCE_TYPES`) and, when the install was
scheduled by an invocation, MUST ride the submitting correlation (§7, deferred
execution).

**Publisher trust** mirrors host trust: an explicit key pin or domain-anchor
assertion when the operator has one; otherwise trust-on-first-use — the first
*verified* install pins the publisher's key per package, and a later statement
signed by a different key MUST be refused until an operator deliberately
resets the pin. A registry entry MAY carry `publisher_key_id` to pre-pin. The
statement is discovered beside the artifact (the reference convention:
`<artifact-filename>.chp-provenance.json` attached to the release, with a
repository-committed `provenance/v<version>/` directory as fallback) or
supplied explicitly.

**Publisher-key rotation** reuses §3.2: a statement MAY carry the publisher's
`key_history` (continuity statements, omitted when empty — pre-rotation
statements are byte-identical). A verifier pinned to an earlier key MUST
accept the new key only by walking the chain from its OWN pin, each hop
verified under the key trusted so far — self-published history cannot
self-vouch. An unwalkable change of key remains a hard mismatch; recovery is
the deliberate pin reset.

## 10. Mandates — Delegated Authority

Evidence proves what happened; anchors prove who; provenance proves what code
ran. This section makes **authority itself** verifiable: today "agent A acts
through host B" rides a static pre-shared key — out-of-band, unscoped in
time, unverifiable by third parties. A **mandate** is a principal's signed,
expiring, capability-scoped grant to a named delegate:

```json
{
  "kind": "mandate", "mandate_id": "mnd_…",
  "delegate_id": "steward-x",
  "scope": ["demo.echo", "chp.adapters.audit.*"],
  "valid_from": "…", "valid_until": "…",
  "created_at": "…", "canonicalization": "chp-stable-v1",
  "principal": { "host_id": "…", "public_key": "…",
                 "host_identity": { …attestation (§3), anchors (§3.1)… },
                 "key_history": [ …§3.2, omitted when empty… ] },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "…" }
}
```

The third member of the statement family (signed bundles §3, adapter
provenance §9), and it composes the existing primitives rather than adding new
ones: the signature covers the canonical header (`kind, mandate_id,
delegate_id, scope, valid_from, valid_until, created_at, canonicalization` —
`scope` sorted at signing time); the principal's attestation answers *whose
authority* through the same trust roots as everything else (§3.1 anchors, §3.2
rotation continuity, omit-when-empty byte rules); `scope` uses the
[http-binding](chp-http-binding.md) §2 grammar (exact capability id or
trailing-`*` prefix). `valid_until` is REQUIRED — unbounded authority is what
this object replaces. Schema:
[mandate.schema.json](../schemas/mandate.schema.json); fixture:
`spec/test-vectors/mandate.json` (verified by both reference implementations
and `verify.mjs`).

**Presentation.** An `InvocationEnvelope` MAY carry a `mandate` (additive —
an envelope without one behaves exactly as before). The receiving host
verifies it **offline** at pipeline gate 5
([chp-invocation-pipeline.md](chp-invocation-pipeline.md) §3): signature,
principal attestation, the validity window **at host time** (never the
client-asserted `requested_at`), and — when transport auth has already
verified a caller — that the mandate names that caller as `delegate_id`.
Verification failure is a PROCESSED denial with the reserved code
`mandate_invalid` (`retryable: false`); an invocation outside a valid
mandate's scope is `policy_blocked` (the §2 caller-key semantics).

**Subject binding.** A valid, in-scope mandate rebinds the evidence subject to
`{id: <delegate_id>, type: "mandate", verified: true, mandate_id, principal:
<principal host_id>}` — "B acted under A's mandate M" lands in the signed
chain with no new event types, replayable and offline-verifiable. A mandate
**narrows and attributes — it never bypasses**: transport auth still gates the
connection, and every later pipeline gate still applies.

**Principal trust.** The attestation verifies offline with no prior
relationship; anchors (§3.1) upgrade *self-declared* to *externally rooted*.
A verifier MAY additionally require the principal's key to match a mesh pin.
Revocation lists, `max_invocations` enforcement, and sub-delegation are
deliberately out of scope for v0.2.3 — expiry (`valid_until`) is the v1
revocation story, mirroring the §3.2 posture that authority recovery is a
deliberate operator act.

**Forwarding.** An intermediary that forwards an invocation (a gateway routing
to member hosts) MUST forward a presented `mandate` **unchanged** on the
forwarded envelope ([proposal 0004](proposals/0004-mandate-forwarding.md)).
The intermediary does not verify it; the **executing host's** gate 5 does, and
rebinds the evidence subject to the delegate-under-principal binding. Per-hop
transport subject rebinding is expected and unchanged — the mandate is the
identity/authority carrier that survives hops, so the front-door caller's
authority lands verified in the executing host's signed chain regardless of
how many intermediaries sit between. Delegate binding composes with transport
auth where that auth verified the original caller (the front door); the
executing host enforces signature, attestation, window, and scope in full.
Mandate re-issuance/attenuation at intermediaries (sub-delegation) is
deliberately out of scope.

## 11. Routing & Reachability

Evidence, identity, supply chain, and authority are governed; this section
brings the last silent layer — **the routing fabric between hosts** — onto the
same plane ([proposal 0003](proposals/0003-reachability.md)). The binding's
load-bearing rule (processed = evidence, denial = HTTP 200) applies to a
routing intermediary at its own layer.

**Unreachability is a governed decision.** When an intermediary can reach no
owner of the requested capability, the invocation was PROCESSED — the
intermediary decided it could not be placed. It MUST return a denial with the
reserved code `host_unreachable` (`retryable: true` — the first reserved
transport code; reachability is transient state that may clear). `details`
SHOULD carry `attempted_hosts`, `last_error`, and `retry_after_s` (honest
advice derived from the intermediary's health-recheck window). A capability
unknown mesh-wide is `capability_not_found`. A **single host never emits
`host_unreachable`** — the code means "the mesh could not reach the work",
never "the work failed". The denial rides the standard `execution_denied`
event; no new denial event type exists.

**Health transitions are evidence.** `ROUTING_EVIDENCE_TYPES` reserves
`host_marked_unhealthy` and `host_marked_healthy` — events an intermediary
emits about its own routing state, on its **own chain** (the §3.1 self-events
precedent), with `host_id` = the intermediary. Emission MUST be
transition-gated: only an actual state change emits (a success against an
already-healthy host is silence). A transition that occurs while routing an
invocation MUST ride that invocation's correlation — the failover is then
replayable in-context: `host_marked_unhealthy` followed by the next
candidate's `execution_started` IS the failover record, which is why no
separate failover event type is reserved (derivable is not reserved).

**Intermediary evidence posture.** An intermediary MUST return processed
denials per the binding; it MUST record them (and its health transitions) as
evidence when it maintains an evidence store, and SHOULD maintain one. A
storeless embedded router remains conformant at the returned-denial floor. An
intermediary with a store merges its own events into stitched replay
timelines, so the mesh's reliability story is part of the replayable record —
not an operational side channel.

**Retry stays with the caller.** The intermediary's owner-failover is the
retry that helps; `retryable: true` plus `retry_after_s` tells the caller when
a retry becomes worthwhile. This spec deliberately defines no automatic client
retry, no active prober, and no unhealthy-state persistence — named deferrals
in proposal 0003, waiting on demand. (The reference implementation provides
a client retry and an active prober as opt-in, non-normative features; the
spec still defines neither.)
