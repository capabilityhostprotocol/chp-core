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

A conforming host prints **`[wire] 16/16`**. The 16 checks: capability
declaration + discovery, envelope invocation, correlation propagation, evidence
on success / failure / denial, replay by correlation, standard denial codes, the
four governance gates (approval-required, budget-exceeded, risk-tier,
safety-guardrail), chain verification over `/verify`, the public identity
document at `/.well-known/chp-identity` (spec §3.1 — assurance tier declared;
at the signed tier the self-attestation must verify), and the export route
(binding §4a — the exported bundle must verify offline at the declared tier).

The runner drives your host purely over HTTP through the reference client. What
it asserts (outcomes, reserved denial codes, event sequences, the 200-for-denied
rule) is specified in [FIXTURES.md](FIXTURES.md) +
[chp-invocation-pipeline.md](../spec/chp-invocation-pipeline.md) — so you
implement from the spec, not from reading a reference.

*Worked example:* `node packages/chp-host-ts/dist/bin/serve.js --port 8899 --key k`
then `python conformance/runner.py --url http://localhost:8899 --key k --suite wire`.

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

A host that prints `16/16` on suite `wire` **and** passes the §2 interop checks
is CHP-conformant at the tier it declares in `/host` (`assurance`:
`hash-chain` or `signed`). Record the runner output as your evidence.
