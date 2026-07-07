# chp-host

Multi-host tooling for the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core):
a config-driven adapter host server, a gateway router that federates evidence
across hosts, mesh key-pinning, and the portable onboarding wizard.

```bash
pip install chp-core chp-host
```

## Start here

```bash
chp-host onboard /path/to/your/repo   # what could YOUR codebase contribute? (pure stdlib, read-only)
chp-host serve --profile host.json    # serve adapters as a governed CHP host
chp-host mesh list                    # see your mesh; verify-keys pins signing keys
```

`chp-host onboard` scans a Python codebase and surfaces candidate capabilities,
then either **wraps existing functions deterministically** into a governed,
evidence-emitting adapter (Mode A) or **hands a conformance-gated spec to your
own coding agent** (Mode B). See
[docs/onboarding.md](https://github.com/capabilityhostprotocol/chp-core/blob/main/docs/onboarding.md).

The gateway (`chp-host gateway`) routes invocations across member hosts,
assembles cross-host **task bundles** (signed, offline-verifiable evidence for
a whole federated task — spec §8), and checks member signing keys against your
pins on the data path.

## License

Apache-2.0 — part of the CHP reference implementation.
