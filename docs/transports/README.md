# CHP Transport Bindings

CHP v0.1 is transport-agnostic. A host can be conformant without HTTP, MCP, Zenoh, Kafka, or any distributed substrate.

Transport bindings are optional integration layers that carry CHP protocol objects across process or network boundaries.

Candidate bindings:

- Local in-process calls: reference implementation in `packages/python/chp_core`
- MCP bridge: prototype in `examples/mcp-bridge-demo`
- Zenoh mesh: see `docs/archive/zenoh-transport-legacy.md` (legacy design note)
- HTTP: implemented in `packages/chp-adapter-http`
- Event streams: future evidence export binding

Transport binding requirements:

- Preserve caller-provided correlation IDs.
- Preserve invocation outcome semantics.
- Emit or carry required evidence events.
- Avoid requiring raw payload logging.
- Define how transport errors map to CHP failures or denials.
