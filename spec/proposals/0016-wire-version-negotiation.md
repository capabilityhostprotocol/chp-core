# 0016: Wire-Version Negotiation — a Specified Path for the First Non-Additive Change

- **Status:** shipped (spec v0.4.1, chp-core 0.24.0, npm alpha.17)
- **Issue:** rad:359abe0
- **Affects:** chp-v0.2.md (new **§ Version negotiation** — a host declares the wire
  versions it speaks; a client selects the highest mutually-supported one; a
  defined rejection when there is no overlap); chp-http-binding.md (the optional
  `X-CHP-Version` request header + its `version_unsupported` rejection);
  `host-descriptor` schema (`supported_versions` field); the reserved denial-code
  registry (`version_unsupported`). **Additive** — no signed bytes move; a
  descriptor omitting `supported_versions` is byte-identical and a request
  omitting the header behaves exactly as today. Discharges the deferral in
  [spec/README.md] ("Version negotiation is deliberately deferred… Revisit when a
  non-additive change is proposed"). First 1.0-readiness infrastructure item.
  Spec **v0.4.0 → v0.4.1**.

## Problem

`protocol_version` is a static string (`"0.2"`) stamped on every wire object but
**never negotiated**. A client cannot learn which wire versions a host speaks —
the descriptor advertises a single version, there is no set — and there is **no
defined behavior on mismatch**: a host silently processes whatever it receives.
Every change to date has been additive (a v0.1-only host still interoperates at
the shared floor), so this has never bitten. But 1.0 needs the negotiation path
**specified before it is needed and exercised by conformance**, so the first
non-additive change (if one is ever proposed) has a proven path rather than one
invented under pressure. The spec has consciously deferred this
([spec/README.md]); this proposal discharges that deferral by shipping the
mechanism as forward-looking infrastructure — not by making a breaking change.

## Design

Three additive parts, mirroring the canonicalization-dispatch idiom from
proposal 0015 (named values, default-when-absent, dispatch on the value,
unknown → reject not crash):

**1. Declare.** A single source of truth `SUPPORTED_VERSIONS = ("0.1", "0.2")`
(the wire lineage — the spec's minor feature versions 0.3.x/0.4.x still speak
wire `"0.2"`, an additive superset of `"0.1"`). The `/host` descriptor gains
**`supported_versions`**: the ordered list of wire versions the host speaks.
**Absent ⇒ `[protocol_version]`** — every existing descriptor consumer is
unaffected, and a bare v0.1 host advertises `["0.1"]`. `protocol_version` stays
the host's *preferred* (highest) version for back-compat.

**2. Select.** A pure `negotiate_version(client_versions, host_versions) → str |
None`: the highest version present in both, compared as `(major, minor)` tuples;
`None` when the sets are disjoint. Both a client and a routing intermediary use
it to choose which version to speak. This is the whole negotiation algorithm —
deterministic, offline, no round-trip beyond the descriptor a client already
fetches via `discover()`.

**3. Reject (the enforced path).** Advertisement alone is advisory; the *path*
requires a channel for the client to declare its choice and the host to honor or
refuse it. The HTTP binding gains an **optional `X-CHP-Version` request header**:

- **Absent** → the host processes under its default (`protocol_version`) exactly
  as today — full back-compat, no client is required to send it.
- **Present and in `supported_versions`** → the host processes under that
  version (and a future non-additive host MAY branch on it — the point of the
  seam).
- **Present and NOT supported** → the host **MUST reject** with HTTP `400` and a
  `version_unsupported` denial code (a new reserved code), rather than silently
  processing under a version the client did not ask for. This is the
  "MUST reject rather than silently degrade" rule already applied to the
  assurance tier, extended to the wire version.

A client that finds `negotiate_version` returns `None` MUST NOT invoke and
surfaces `version_unsupported` locally — the symmetric client-side half.

**Consolidation.** This is the versioning arc, so it also collapses the three
disconnected version literals (`types.py` descriptor default `"0.1"`,
`signing.py` bundle default `"0.2"`, `http.py` tier-derived override) onto the
`SUPPORTED_VERSIONS`/`PROTOCOL_VERSION` constants and fixes the `/host` descriptor
reporting `"0.1"` in-process but `"0.2"` over HTTP. Signed bytes are untouched
(the bundle header `protocol_version` stays `"0.2"`, byte-identical to every
vector).

## Compatibility

Additive. `supported_versions` is a new descriptor field (omit-when-you-want →
defaults to `[protocol_version]`); `X-CHP-Version` is an optional header (absent
→ current behavior); `version_unsupported` is a new reserved denial code. No
canonicalization, hashing, or signing changes — every `spec/test-vectors/`
fixture verifies unchanged (the byte gate). A **patch** bump (v0.4.1): the
mechanism adds a field, a header, and a code, and moves no existing bytes.

Deferred by design: a second WIRE version (there is only the `0.1`/`0.2` lineage
— this proposal builds the negotiator for when one is needed, exactly as 0015
built the second canonicalization to prove that seam); per-request version
branching in handler logic (hosts may branch on the negotiated version, but no
capability does yet); binding-specific carriers other than HTTP (the abstract
mechanism lives in chp-v0.2.md, the `X-CHP-Version` carrier in
chp-http-binding.md — another binding defines its own carrier).

## Shipped as

- **Spec v0.4.1** — chp-v0.2.md **§1.1** (declare `supported_versions` → select
  the highest mutual → reject an unsupported explicit version); chp-http-binding
  §2 (the optional **`X-CHP-Version`** header + its `400` `version_unsupported`);
  `version_unsupported` registered in the governance + pipeline denial-code
  vocabulary; `host-descriptor` schema `supported_versions`; the README deferral
  discharged.
- **chp-core 0.24.0** — `SUPPORTED_VERSIONS`/`PROTOCOL_VERSION` (one source of
  truth), `negotiate_version`, `versions_upto`, `HostDescriptor.supported_versions`
  (derived when absent), `version_unsupported` reserved code; `/host` + `/health`
  serve a consistent version via `_served_protocol_version`; the
  `_reject_unsupported_version` guard on every request; `RemoteCapabilityHost.
  negotiate()`. Also collapsed the three disconnected version literals and fixed
  the `/host` `0.1`-in-process vs `0.2`-over-HTTP split.
- **npm alpha.17** — chp-sdk `version.ts` (`negotiateVersion`/`versionsUpto` +
  constants) + `client.negotiate()`; chp-host-ts declares `supported_versions`
  and rejects an unsupported `X-CHP-Version`.
- **Guards** — `spec_defines_version_negotiation` + `descriptor_declares_supported_versions`
  (alignment 79 → 81); wire check `check_version_negotiation` (declare → select →
  reject), PASSES black-box against both reference hosts.

Deferred (unchanged from Design): a second WIRE version (the negotiator is built
for when one is needed); per-request version branching in handler logic;
binding-specific carriers other than HTTP.
