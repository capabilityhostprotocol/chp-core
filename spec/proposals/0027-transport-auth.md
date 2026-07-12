# 0027: Normative Transport / Auth Binding + Signed Bearer Tokens

- **Status:** shipped (spec v0.7.2, chp-core 0.35.0, npm alpha.26)
- **Issue:** rad:8012e20c
- **Affects:** chp-v0.2.md §5 (promoted from *"informative for v0.2"* to
  **normative**, reconciled with the already-normative `chp-http-binding.md`) + a
  new **`auth-token`** statement: an ed25519-signed, short-lived, audience-bound
  bearer token a caller presents instead of (or beside) the static `X-CHP-Key`.
  **Additive** — the static shared key still authenticates; tokens are an opt-in
  stronger credential. **No new denial code** — a bad/expired token is a transport
  **401**, before the pipeline (like a bad key today). Spec **v0.7.1 → v0.7.2**.

## Problem

§5 has been "informative for v0.2" since the start, while the real, testable auth
rules live (normative) in `chp-http-binding.md` — a documentation-coherence gap.
Worse, the only credential is a **static shared secret** (`X-CHP-Key`): the host
*stores* every caller's key, a leaked key never expires, and a key captured for one
host replays to any host that shares it. For a mesh of mutually-authenticating
hosts with ed25519 identities already in hand, a signed-token model is the natural
fit — and nothing in §5 requires TLS.

## Design

**Normative §5.** TLS (or equivalent network-layer confidentiality) **MUST**
protect the transport; credential comparison **MUST** be constant-time (it already
is — `hmac.compare_digest`, `http.py`); a host **MUST** bind an authenticated
caller to a verified `subject` on the evidence. The stale "informative" label is
removed and §5 points at the binding doc as its normative detail.

**Signed bearer tokens (`auth-token`).** A caller mints a token signed by its
ed25519 identity key:

```json
{ "kind": "auth-token", "sub": "<caller host_id>", "aud": "<target host_id>",
  "iat": "<ISO-8601>", "exp": "<ISO-8601>", "canonicalization": "chp-stable-v1",
  "caller": { "host_id", "public_key", "host_identity": { … } },
  "signature": { "algorithm": "ed25519", "key_id", "signature" } }
```

The signature covers the canonical header `{kind, sub, aud, iat, exp,
canonicalization}`; the `caller` block is the same self-attested identity a mandate
principal carries. Presented over the wire as `X-CHP-Token: <json>` (or
`Authorization: Bearer <base64url(json)>`).

**Verification is two-part.** (1) `verify_auth_token(token, aud, at_time)` — the
statement is internally valid: structure, header signature against
`caller.public_key`, the caller attestation binds `host_id == sub` to that key,
`iat ≤ at_time < exp`, and `aud` matches this host. (2) The host **authorizes** the
caller: `sub`'s pinned public key (config `CHP_HOST_TOKEN_KEYS="sub:pubkey,…"`)
MUST equal `caller.public_key` — so the host pins *which* callers may present
tokens, exactly as `CHP_HOST_API_KEYS` pins which shared keys are valid. A valid,
authorized token sets the verified caller to `sub`. Any failure is a transport
**401** (never a `200` governance denial), like a bad `X-CHP-Key`.

**Why this beats the static key.** The host stores only the caller's *public* key
(a leaked host config leaks no caller secret); the token **expires** (a captured
token is useless after `exp`); and `aud` binds it to one host (no cross-host
replay). It reuses the whole identity/attestation/anchor stack — no new PKI, no
external IdP, no new dependency.

## Compatibility

Additive. The static `X-CHP-Key` path is unchanged and still authenticates; a host
that configures no token pins simply never accepts tokens. No wire object, bundle,
or signature format changes; `auth-token` is a new signed statement in the same
family as mandates/witnesses. No new reserved denial code (transport 401). A
**patch** bump (v0.7.2): it makes an existing section normative and adds an
optional credential, no existing bytes move.

## Deferred by design

mTLS and OIDC/JWT (external-IdP) auth; token **revocation lists** (short expiry is
the mitigation — a token is its own bounded-lifetime grant, like a mandate);
refresh-token flows / automatic renewal; delegated-audience (a token valid for a
set of hosts); binding a token to a specific TLS channel (token-binding /
DPoP-style proof-of-possession).

## Shipped as

- **Spec v0.7.2** — chp-v0.2.md §5 normative (TLS/constant-time/subject-binding
  MUST) + the `auth-token` bearer credential; new `auth-token` schema.
- **chp-core 0.35.0** — `signing.build_auth_token`/`verify_auth_token`/
  `auth_token_header`; `http._check_auth` accepts `X-CHP-Token`/`Authorization:
  Bearer` beside `X-CHP-Key`, pinning `sub`'s key via `CHP_HOST_TOKEN_KEYS`.
- **npm alpha.26** — chp-sdk `verifyAuthToken` + `buildAuthToken` (byte-parity;
  TS verifies the Python token).
- **Vectors + guards** — `auth-token.json` (verifies in Python + TS SDK +
  `verify.mjs`; wrong-aud/tampered rejected); `spec_defines_transport_auth` +
  `auth_token_vector_verifies` (alignment 101 → 103); the live-HTTP
  `test_transport_auth` covers the wire path (real 401s).

Deferred (unchanged): mTLS, OIDC/JWT, token revocation lists, refresh flows,
delegated audience, channel-bound tokens (DPoP).
