# Capability Host Protocol — v0.2 (Evidence Integrity)

Status: **released** (v0.2 2026-07-06; v0.2.1–v0.2.9 additions 2026-07-09/11; **v0.3.0 selective disclosure**; **v0.3.1 streaming completion**; **v0.3.2 witness quorum + anchoring**; **v0.3.3 gateway exactly-once**; **v0.4.0 chp-jcs-v1 second canonicalization** 2026-07-11). Changes via [proposals/](proposals/) — see [CHANGELOG.md](CHANGELOG.md). **Additive** over [v0.1](chp-v0.1.md); a v0.1-only host remains
conformant at the `none` assurance tier. v0.2 defines an *optional* tamper-
evident evidence layer without changing the v0.1 local-first experience. v0.3.0
adds the first *canon evolution* — a second, opt-in content-hash scheme
(`chp-event-hash-v2`, §2 + §14) that leaves every v1 event byte-identical.

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
cross-language interoperability.

**Second canonicalization (`chp-jcs-v1`).** Since v0.4.0
([proposals/0015](proposals/0015-chp-jcs.md)) the `canonicalization` field is a
real **dispatch seam**: a verifier MUST select the header-signature serializer by
the bundle's `canonicalization` value (absent/legacy → `chp-stable-v1`).
**`chp-jcs-v1`** is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JCS —
identical structure to chp-stable-v1 except: **compact separators** (`,` / `:`,
no spaces); **raw-UTF-8 strings** (`café`, `🔒` literal, not `\uXXXX`); **keys
sorted by UTF-16 code unit** (identical to chp-stable-v1 for the BMP, differing
only for astral-plane keys). Numbers are integers as bare decimal — **rule 6 (no
floats in hashed content) is retained across ALL schemes**, so RFC 8785's
ECMAScript number-formatting algorithm is never exercised by CHP content
(deferred). chp-jcs-v1 governs the **bundle-header signature** only; the
per-event content-hash is the orthogonal `hash_scheme` axis (below). A future
scheme MAY likewise be added non-breakingly through the field.

**Content-hash schemes (`hash_scheme`).** The rule above is
**`chp-event-hash-v1`** — the default, selected when an event carries **no**
`hash_scheme` field (as every v0.1/v0.2 event does). v0.3.0 defines a second,
opt-in scheme **`chp-event-hash-v2`** (§14, [proposals/0011](proposals/0011-selective-disclosure.md)):
the stable object is identical except the `payload` member is replaced by
`"payload_commitment": sha256(chp-stable-v1(payload))`, so the payload is
committed by hash and can later be *withheld* from a bundle without changing the
`content_hash`. An event names its scheme with the `hash_scheme` field; a
verifier MUST recompute each event's hash under the scheme that event declares
(so a chain MAY mix v1 and v2 events). The `canonicalization` field still names
the **bundle-header** canon (`chp-stable-v1`); `hash_scheme` is the **per-event**
content-hash rule — the two are orthogonal.

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
`scope` sorted at signing time; a sub-mandate's header additionally covers
`depth, parent_id`, Sub-delegation below); the principal's attestation answers *whose
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
`max_invocations` enforcement remains deliberately out of scope; expiry
(`valid_until`) is the floor every host enforces, revocation (below) upgrades
recovery, and sub-delegation (below) extends a mandate into an
attenuation-only chain.

**Revocation** ([proposal 0007](proposals/0007-revocation-distribution.md)).
A principal MAY withdraw a mandate before its expiry with a
**mandate-revocation** — the fifth statement-family member: the signature
covers the canonical header (`kind, mandate_id, revoked_at, reason,
canonicalization`), with the principal's attestation embedded. The
**issuer-only rule** is load-bearing: a revocation binds to a mandate by
`mandate_id` AND by principal-key match, and a verifier MUST check the
revocation signature against the **mandate's** `principal.public_key` —
never the statement's self-declared key, which would let anyone revoke
anyone's mandate by naming its id. A statement signed by any other key
revokes nothing. Once a valid revocation is known the mandate is invalid at
all times (revocation is not a validity-window edit); gate 5 returns the
existing `mandate_invalid` denial — no new code. Distribution is push +
pull, host-local: `POST /revocations` delivers a statement (the receiving
host MUST verify signature + attestation before persisting — an
unverifiable statement is refused, never stored); `GET /revocations` serves
the host's full revocation set `{keys, mandates}` — the §3.2 key
revocations thereby gain a standalone wire surface beyond the identity
document. Received mandate revocations live in sidecar storage, NEVER in
the §3.2 key-revocation file the identity document serves verbatim.
Propagation is best-effort by design (no gossip, no global list): a host
that never receives the statement keeps honoring the mandate until expiry —
exactly the pre-0007 posture, which remains the conformance floor. Schema:
[mandate-revocation.schema.json](../schemas/mandate-revocation.schema.json);
fixture: `spec/test-vectors/mandate-revocation.json` (verified by both
reference implementations and `verify.mjs`).

**Sub-delegation** ([proposal 0009](proposals/0009-sub-delegation.md)). A
delegate MAY re-delegate a **narrowed** slice of its authority to a
sub-agent, forming an **attenuation-only mandate chain**. A sub-mandate is a
mandate with three additional fields: `parent_id` and `depth` (in the signed
header, present only when `parent_id` is set — so a root mandate is
byte-identical to a single-hop one) and `parent` (the full parent mandate
embedded inline, recursively; carried as transport, verified on its own
signature). The sub-principal is the parent's delegate: the holder of the
parent mandate signs the child with its **own** key — no key sharing, no root
involvement.

The load-bearing invariant is **monotone attenuation: a child can only
NARROW scope and SHORTEN the window, never widen or extend.** A verifier
walks the chain link-by-link. For each child→parent link it MUST check:
`depth == parent.depth + 1` (root depth 0) and `depth` within an
implementation cap; `parent_id == parent.mandate_id`; the **delegate join**
— `parent.delegate_id == child.principal.host_id` (the parent delegated *to*
this sub-principal); `scope ⊆ parent.scope` (every child scope entry matches
the parent under the §2 grammar); and `[valid_from, valid_until] ⊆` the
parent's window. It then recurses into `parent` (carrying host time and the
revocation set, not the leaf's delegate/capability bindings) to the root (no
`parent`) — ordinary single-hop verification. Every hop verifies under the
key in its own `principal.host_identity`, so the whole chain verifies
**offline, with no prior relationship** — the single-hop trust model made
inductive.

At gate 5 the caller binds to the leaf's `delegate_id`, ancestors bind via
the join, and the leaf's scope gate stays correct because leaf ⊆ every
ancestor by induction. The evidence subject additionally records the
**root principal**, so the signed chain shows both the acting delegate and
the ultimate authority. Revocation composes for free: each link's
`not_revoked` check runs against that link's own principal key, so revoking
any ancestor kills the whole leaf chain. A bad chain — attenuation
violation, broken join, over-depth, or a revoked ancestor — is the existing
`mandate_invalid` denial; no new code. Schema:
[mandate.schema.json](../schemas/mandate.schema.json) (the three additive
optional fields); fixture: `spec/test-vectors/mandate-chain.json` (verified
by both reference implementations and `verify.mjs`).

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
Alternatively an intermediary MAY re-issue an **attenuated** sub-mandate
(embedding the received mandate as `parent`, Sub-delegation above) before
forwarding — narrowing authority as work fans out; forwarding a mandate
unchanged remains valid and is the floor.

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

## 12. Witnessing — Tamper-Proof Against the Operator

Evidence is tamper-evident; this section makes it tamper-proof **against the
host's own operator** ([proposal 0005](proposals/0005-mesh-witnessing.md)).
Signing happens at export, but the store is operator-controlled — between
exports, history could be rewritten and re-signed. The fix: **peers
countersign each other's chain heads**, and the countersignature lives with
the witness, where the witnessed operator cannot delete it.

**The store head (`chp-store-head-v1`).** Evidence chains are per-correlation
over one global, never-rewinding sequence. The witnessable digest: for every
correlation, its head `content_hash` at global sequence ≤ N; the store head is
SHA-256 over the sorted `correlation_id\x00head_hash\n` lines. Because chains
are append-only, the head **as-of any witnessed N is recomputable later** —
that recomputability is the mechanism: rewriting anything at sequence ≤ N
changes some correlation's head, and the recomputed root stops matching what
a peer signed.

**The `chain-witness` statement** — the fourth statement-family member
(bundles §3, provenance §9, mandates §10): the witness signs the canonical
header `{kind, host_id (witnessed), sequence, store_head, witnessed_at,
canonicalization}` — plus `revocation_head` when the witnessed head carried
one (Revocation freshness below; present only when set, the §10
omit-when-empty rule, so a pre-0010 statement is byte-identical) — with the
witness's attestation (anchors §3.1) embedded. The witness signs only the
**root(s)**; the witnessed host's correlation ids and revocation ids never
leave it. Schema:
[chain-witness.schema.json](../schemas/chain-witness.schema.json); fixture:
`spec/test-vectors/chain-witness.json` (verified by both reference
implementations and `verify.mjs`).

**Exchange.** `GET /head` (authed — the sequence discloses activity volume)
returns `{host_id, scheme, sequence, store_head, revocation_head, at}`. A
witness fetches it, builds the statement, and `POST /witness` delivers it; the
witnessed host MUST verify the signature **and recompute its own head at that
sequence** — and its own `revocation_head` — before persisting, never storing
an unverified or non-matching receipt (`revocation_head_mismatch`, 409). On
acceptance the witnessed host snapshots its leaves-at-N and its
revocation-identifier set beside the statement (the signed roots make the
snapshots tamper-evident). `GET /witnesses` (authed) serves
received statements — a host publishing third-party countersignatures over
its own history. The witness retains every statement it issued: those records
are the threat-model core. Witness records MUST NOT enter the evidence store
(a witness event would draw a sequence and move the head being witnessed) —
they live in sidecar storage.

**Verification and retention.** Retention lawfully deletes whole correlations
(purge) and lawfully NULLs hashes (redaction); witnessing must not brand
lifecycle operations as attacks. Auditing (`chp witness verify --store`)
recomputes the head as-of each witnessed sequence and judges **per leaf**
against the snapshot: match → `verified`; correlation absent → `purged`
(legal); head NULLed → `redacted` (legal — redaction can only NULL, never
forge a different valid hash); differing hash → **`tampered`**; a correlation
present at ≤ N but missing from the snapshot → **`tampered`** (inserted
history). Honest lifecycle and rewriting are thereby distinguishable with no
witness-expiry rules.

**Revocation freshness** ([proposal 0010](proposals/0010-revocation-freshness.md)).
Revocation (§10) is best-effort push, and a host could silently drop a
revocation it received with no way to prove otherwise. The fix rides this
same channel: a **`chp-revocation-head-v1`** digest — SHA-256 over the held
revocation *identifiers* (`m\x00{mandate_id}\x00{principal.public_key}\n` per
mandate revocation, `k\x00{revoked_key_id}\n` per key revocation, sorted;
identifiers, never the statements, so re-serialization does not move the
head; a host with none has the well-defined empty-set digest) — is bound into
the witnessed head. The witness countersigns `revocation_head` alongside
`store_head`; the witnessed host recomputes its own before persisting a
receipt and snapshots its revocation-identifier set beside it. An auditor
(`chp revocation verify`) recomputes the digest over a snapshot to prove it
is what a peer signed, then compares snapshots and the current set: because
the held set is append-only, **an identifier present in an earlier witnessed
snapshot but absent later is a `dropped` revocation — a provable denial of
revocation.** The witness signs only the digest; no revocation id leaks to
peers. Lawful revocation-expiry dispositions and cross-mesh freshness quorum
are out of scope (named in proposal 0010).

**Witness quorum** ([proposal 0013](proposals/0013-witness-quorum.md)). One
witness is a single point of collusion, and every witness is a peer the
operator's mesh controls. **`chp-witness-quorum-v1`** turns the collected
`chain-witness` statements into an anti-collusion proof: an auditor verifies
each statement, keeps only those over the EXACT `(host_id, sequence,
store_head)`, **dedupes by the witness's `key_id`** (a witness re-submitting
counts once — quorum measures distinct identities, not statement volume),
optionally restricts to a trusted witness set (the *n*), and counts. The
verdict is **`quorum_met`** (distinct witnesses ≥ *k*) or **`quorum_short`** —
"≥*k* independent parties countersigned this exact head." The policy (*k*, and
optionally the *n* set) is host config; the witness loop is unchanged (it still
countersigns every remote), and `quorum_short` is an audit verdict, never a gate
denial. No new canonical object — quorum aggregates statements that already
exist, so every published vector is byte-identical.

**External anchoring** ([proposal 0013](proposals/0013-witness-quorum.md)).
Quorum still depends on *our* peer set; **`chp-store-head-anchor-v1`** binds a
head to a party OUTSIDE the mesh, so an independent record survives even if all
witnesses collude. A `store-head-anchor` statement — `{kind:"store-head-anchor",
host_id, sequence, store_head, anchored_at, anchor:{type:"did", did,
countersignature}}` — carries an external `did:key`'s ed25519 **SSHSIG
countersignature** over `chp-stable-v1({kind, host_id, sequence, store_head,
anchored_at})` (SSHSIG namespace `chp-store-head-anchor`, the §3.1 DID-anchor
mechanism applied to a store head instead of a key), verified fully offline. The
anchor key is a designated notary or a transparency-log checkpoint key. Real
transparency-log (Rekor/Sigstore) Merkle-inclusion proofs + gossip are out of
scope (named in proposal 0013) — this is the signed-checkpoint form.

**Cadence and posture.** Any authed peer MAY witness any peer; the reference
gateway carries an opt-in witnessing loop (`gateway.witness_interval_s`,
default off — the prober pattern). A host that neither issues nor accepts
witnesses remains conformant at the export-signing floor; witnessing upgrades
the assurance story from tamper-evident to tamper-proof-against-the-operator.
Witness-of-witness chains and cross-mesh witnessing are deliberately out of
scope (named in proposal 0005).

## 13. Reliability — Idempotent Replay

Retry stays with the caller (§11), but §11's honest caveat — a connection
that drops after execution leaves "never ran" indistinguishable from "ran,
response lost" — made every retry of non-idempotent work a gamble. This
section closes it ([proposal 0008](proposals/0008-idempotent-replay.md)):
**a host that has already recorded an invocation's `invocation_id` MUST NOT
re-execute it; it returns the recorded result.**

The idempotency key is the envelope's existing `invocation_id` — no new
header or field. A caller that wants retry-safety presents the SAME id on
every attempt; a fresh id (the default) always means a fresh execution.
Replay covers every processed outcome — `success`, `failure`, `denied`,
`skipped` — and, since v0.3.1, **streaming invocations too** (§13.1); a
replayed denial is the same denial and gates do not re-run (their decision is
part of the recorded outcome). The base scope is a single host: replay happens
only on the host that served the original. Cross-owner dedupe at a **gateway** —
so a router failing over between owners does not double-execute — is **§13.2**
(since v0.3.3).

**The result cache is serving state, never evidence.** Evidence remains the
audit record and deliberately does not persist handler result data; the
recorded result lives in a host-local, window-bounded cache (reference:
`invocation_results` beside the §12 serving artifacts; default retention
24h). After the window a duplicate id executes fresh — idempotency is a
bounded-window guarantee. Purging a correlation (§12 retention) MUST also
drop its cached results: a lawfully purged invocation must not remain
replayable. A replayed response carries `"replayed": true` on the
`InvocationResult` (omitted when false — additive and byte-stable); no
lifecycle events are appended for an execution that did not happen.

**Security.** Replay is not a new disclosure — the result was already
returned once, and a replay passes the same transport auth (and per-caller
key scope, §2) as any invocation. Ids are 128-bit random by construction; a
host MAY additionally bind replay to the original caller identity.

With this section, the reference client's opt-in retry and the reference
gateway's owner-failover reuse ONE `invocation_id` across attempts, making
both provably safe against replay-conformant hosts. Distributed result
caches and an `invocation_replayed` evidence type are deliberately out of
scope (named in proposal 0008).

### 13.1 Streaming replay & resume

*(v0.3.1, [proposals/0012](proposals/0012-streaming-completion.md).) Idempotent
replay extended to streams, plus mid-stream resume.*

A streaming invocation (`mode:"stream"`, §binding "Streaming invocations")
records its ordered chunk deltas beside the recorded terminal result — serving
state in the same window-bounded cache, **never hashed into the evidence
chain** — and commits a **`chp-chunk-seq-v1`** digest of them into its
`execution_completed` evidence as `chunk_seq_digest` =
`sha256( Σ chp-stable-v1(delta_i) + "\n" )` (the §12 store-head line scheme,
each delta canonicalized so the digest is byte-exact across implementations),
alongside a `chunk_count`. Both fields are **omit-when-absent** — only streaming completions carry them, so a non-stream
event is byte-identical. The digest makes the delivered sequence tamper-evident:
a resumed or replayed stream is verifiable against what was originally
committed. Per-chunk events are NOT emitted (they are transport, not evidence).

- **Replay.** A retried streaming `invocation_id` whose chunks are still cached
  MUST **re-stream the recorded chunks, then the recorded terminal result**,
  with `"replayed": true`; no lifecycle events are appended (the execution did
  not re-happen). If the chunks are no longer cached (cache cap or window
  expiry) the host MAY replay the terminal result as a single degenerate stream
  — still idempotent. A cap on retained chunks/bytes is permitted; over it, a
  stream is recorded non-resumable but still emits its digest.
- **Resume.** Each `event: chunk` SSE frame carries an `id: <n>` line (n =
  0-based chunk index); the terminal `result` frame carries the final id. A
  client whose connection drops reconnects with the **same `invocation_id`** and
  a `Last-Event-ID: <n>` request header; the host resumes from chunk **n+1** off
  the recorded buffer, then the terminal result. Resume is replay-from-offset; a
  fresh replay is resume-from-(-1) — one path. A host that does not implement
  resume answers the reconnect as a fresh stream (the client consumes from the
  start); `id:` is standard SSE a pre-0012 client ignores.

Deferred (proposal 0012): live mid-flight resume (reconnecting to a
still-producing generator), per-chunk hashed events, SSE keep-alive pings,
backpressure, durable cross-restart chunk storage, and cross-host resume.

### 13.2 Gateway exactly-once

*(v0.3.3, [proposals/0014](proposals/0014-gateway-exactly-once.md).) Idempotent
replay extended across a routing gateway's owner set.*

§13's base cache is per-host, so a **gateway** (§11 routing) failing over between
owner hosts can still **double-execute**: reusing one `invocation_id` across
owner-failover attempts lets an owner replay via its own gate 0, but only for a
retry landing on the **same** owner — a cross-owner failover re-executes on a
peer whose separate cache never saw the id, and a gateway that mints its own id
(dropping the client's) cannot dedupe a client retry or survive a restart.

A gateway SHOULD maintain a **result cache keyed by the client's
`invocation_id`** that spans its owners:

- It **preserves the client's `invocation_id` end-to-end** (client → gateway →
  owner), one id for the whole logical operation.
- **Before routing** it checks the cache; on a hit it returns the recorded
  result with `"replayed": true` and **routes to no owner** — a gateway that has
  served an id once never routes it again.
- **On a definitive processed outcome** (success/failure/final denial) it records
  the result — first-write-wins, window-bounded (the §13 result-cache retention),
  spanning owners AND gateway restarts (persistent store). A **retryable**
  outcome — notably `host_unreachable` (§11) — is NOT cached, so a transient
  failure stays retryable.
- The cache is **serving state, never evidence** (like §13); a cache hit emits no
  lifecycle events. No new evidence type or denial code.

This makes a client retry exactly-once across owner **selection, failover, and
gateway restart**. The owner still runs its own §13 gate 0 on the forwarded id.
Deferred (proposal 0014): the honest §11 residual — an owner that executed but
whose response was lost *before reaching the gateway* leaves the gateway unable
to cache what it never saw, so a failover to a different owner still double-
executes (true exactly-once there needs owner-side coordination); owner-pinned /
shared caches; multi-gateway distributed dedupe.

## 14. Selective Disclosure — Withholdable Payloads

*(v0.3.0, [proposals/0011](proposals/0011-selective-disclosure.md).) The first
canon evolution: a second content-hash scheme so a signed bundle can prove a
correlation's control flow while **withholding** the payloads.*

A `content_hash` under `chp-event-hash-v1` (§2) folds the raw `payload` inline,
so verifying a bundle requires every payload — the bundle proves everything or
nothing. **`chp-event-hash-v2`** commits to the payload by hash instead:

- **The scheme.** An event under `chp-event-hash-v2` carries
  `hash_scheme: "chp-event-hash-v2"` and a `payload_commitment` =
  `sha256(chp-stable-v1(payload))` (lowercase hex). Its `content_hash` stable
  object is the §2 object with the `payload` member **replaced by**
  `payload_commitment`; everything else (field set, order, `chp-stable-v1`
  serialization, `prev_hash` link, the root hash, the signature) is unchanged.
  The commitment is over the payload canonicalized by the **same**
  `chp-stable-v1` rules; the empty payload commits as the explicit object `{}`.
- **Withholding.** A *disclosure-minimized* bundle replaces a v2 event's
  `payload` with the marker `{"chp_withheld": true}` and keeps its
  `payload_commitment` and `content_hash`. Because the root hash and signature
  build only on `content_hash`, they are unchanged — **the original signature
  still validates the minimized bundle**. Withholding requires no re-signing and
  never mutates the store; any party holding a signed v2 bundle can produce a
  minimized view of it.
- **Verification.** For each v2 event a verifier recomputes `content_hash` from
  the stable fields + `payload_commitment` (a withheld event verifies — the raw
  payload is not needed). If the event still carries a real `payload`
  (*disclosed*), the verifier MUST additionally check
  `sha256(chp-stable-v1(payload)) == payload_commitment`, binding the disclosed
  value to what was signed; a mismatch is `tampered`. v1 events verify exactly
  as in §2.
- **Coexistence.** `hash_scheme` is absent on every v1 event, so v1 chains,
  store heads, witnessed receipts, and signed bundles are byte-identical and a
  chain MAY mix v1 and v2 events (each self-describes; `prev_hash` links across
  schemes). Hosts SHOULD stamp new events `chp-event-hash-v2` from v0.3.0;
  existing events are not rewritten. A pre-0011 verifier correctly refuses a
  **withheld** v2 bundle (it cannot recompute the hash without the payload) — an
  honest failure, not a false accept.

**Not retention redaction.** §4/§12 *redaction* destroys a stored payload and
NULLs its `content_hash` (→ `unverified`); *purge* deletes whole correlations.
Selective disclosure is the opposite: a non-destructive, verifiable *view* of an
intact signed bundle — it never NULLs, deletes, or forges a hash. The two keep
disjoint vocabularies: **withhold / minimize** (this section) vs **redact /
purge** (§4/§12). No new denial code or evidence type: withholding is a bundle
transform, and a stale/forged disclosure surfaces as the existing `tampered`
verdict, not a gate denial.

Deferred (named in proposal 0011): per-field / sub-payload Merkle commitments,
retroactive v1→v2, withholding non-payload fields, encrypting withheld payloads,
and disclosure receipts.
