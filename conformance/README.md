# CHP Conformance Kit

How anyone — in any language — proves their Capability Host Protocol
implementation is conformant. There are two independent surfaces:

1. **Wire conformance** — your *host* behaves correctly over the HTTP binding.
2. **Canonicalization + signing interop** — your *bytes* match the reference.

A reference second implementation (TypeScript: `packages/chp-sdk`,
`packages/chp-host`) passes both and is the worked example.

## 1. Wire conformance (host under test)

Register the fixture profile ([FIXTURES.md](FIXTURES.md)) and serve your host
over the [HTTP binding](../spec/chp-http-binding.md). Then run the reference
black-box runner against it:

```bash
python conformance/runner.py --url http://localhost:PORT --key <key> --suite wire
```

A conforming host prints **`[wire] 18/18`**. The 18 checks: capability
declaration + discovery, envelope invocation, correlation propagation, evidence
on success / failure / denial, replay by correlation, standard denial codes, the
four governance gates (approval-required, budget-exceeded, risk-tier,
safety-guardrail), chain verification over `/verify`, the public identity
document at `/.well-known/chp-identity` (spec §3.1 — assurance tier declared;
at the signed tier the self-attestation must verify), the export route
(binding §4a — the exported bundle must verify offline at the declared tier),
capability-scoped caller keys (binding §2 — an out-of-scope invocation is a
PROCESSED `policy_blocked` denial with evidence, never a transport 403; the
runner needs `CHP_CONFORMANCE_SCOPED_KEY`, see FIXTURES.md), and the mandate
gate (spec §10 — the runner plays a never-met principal; a valid in-scope
mandate succeeds with the delegate-under-principal subject in evidence, while
out-of-scope / expired / tampered are processed `policy_blocked` /
`mandate_invalid` denials).

The runner drives your host purely over HTTP through the reference client. What
it asserts (outcomes, reserved denial codes, event sequences, the 200-for-denied
rule) is specified in [FIXTURES.md](FIXTURES.md) +
[chp-invocation-pipeline.md](../spec/chp-invocation-pipeline.md) — so you
implement from the spec, not from reading a reference.

*Worked example:* `node packages/chp-host-ts/dist/bin/serve.js --port 8899 --key k`
then `python conformance/runner.py --url http://localhost:8899 --key k --suite wire`.

### 1a. Mesh conformance (routing intermediary under test)

A **gateway** that routes invocations across member hosts has its own
obligations (spec §11 + §10 Forwarding): processed `host_unreachable` denials
(HTTP 200, never a bare 5xx), mandates forwarded unchanged, its own health
transitions merged into stitched replays, partial replays disclosed, partial
exports refused with 503. The `mesh` suite proves them black-box: the runner
hosts two reference member hosts, your gateway routes between them, and the
runner induces failure by killing its own member:

```bash
python conformance/runner.py --gateway-url http://localhost:PORT --suite mesh
```

A conforming intermediary prints **`[mesh] 8/8`**. Topology, gateway config
requirements (evidence store, keyless members, members-first start order),
and the ordered check list: [MESH-FIXTURES.md](MESH-FIXTURES.md).

## 2. Canonicalization + signing interop (bytes under test)

Your `chp-stable-v1` implementation must reproduce the published bytes exactly,
and a bundle you sign must verify under a *different* implementation.

- **Canonicalization golden set:** for every case in
  [`spec/test-vectors/canon/cases.json`](../spec/test-vectors/canon/cases.json),
  `canon(input)` MUST equal `expected_canon` byte-for-byte (surrogate pairs,
  control chars, unicode key-sort, no floats — see
  [chp-v0.2.md §2](../spec/chp-v0.2.md)).
- **Verify reference bundles:** your verifier MUST accept the Python-signed
  `signed-bundle.json` and the *governed* `governance-bundle.json`, and MUST
  reject a tampered or relabelled bundle.
- **Cross-verify your signature:** a bundle *you* sign MUST verify under the
  stdlib Node reference verifier and Python:

```bash
node spec/test-vectors/verify.mjs your-signed-bundle.json          # → VALID
python -c "import sys; sys.path.insert(0,'packages/python'); \
  from chp_core.signing import verify_bundle; import json; \
  print(verify_bundle(json.load(open('your-signed-bundle.json'))).valid)"   # → True
```

*Worked example:* the TS SDK reproduces the golden set byte-for-byte, produces a
**byte-identical** signature to Python for the same input, and a fresh TS-signed
governed bundle verifies VALID under both `verify.mjs` and Python.

## Reference runner internals

The runner ships built-in sample hosts for local development:

```bash
python conformance/runner.py                         # the passing reference host
python conformance/runner.py --sample failing-no-evidence   # a deliberately broken host
python conformance/runner.py --suite normative       # spec MUSTs (in-process)
```

Suites: `normative` (spec MUSTs, in-process) · `reference` (bundled capability
library) · `wire` (black-box HTTP, needs `--url`) · `all`.

## Claiming conformance

A host that prints `18/18` on suite `wire` **and** passes the §2 interop checks
is CHP-conformant at the tier it declares in `/host` (`assurance`:
`hash-chain` or `signed`). Record the runner output as your evidence.
