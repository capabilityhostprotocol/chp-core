# CHP v0.1 Conformance

The conformance suite verifies the minimum behaviors of a CHP-compatible host:

1. Capability declaration
2. Capability discovery
3. Invocation through an envelope-compatible boundary
4. Correlation propagation
5. Evidence emission on success
6. Evidence emission on failure
7. Evidence emission on denial
8. Replay by correlation ID
9. Optional representation of skipped execution, where the host supports disabled or skipped capabilities

Run the passing reference host:

```bash
python conformance/runner.py
```

Run a deliberately broken host:

```bash
python conformance/runner.py --sample failing-no-evidence
```

The runner currently ships with built-in sample hosts. External host adapters
should implement `discover()`, `invoke(...)` or async `ainvoke(...)`, and
`replay(correlation_id)`.

The development host also exposes the conformance matrix as a CHP capability:

```bash
chp work conformance-matrix
```

This records matrix results as CHP evidence under the provided correlation ID.
