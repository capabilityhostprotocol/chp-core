# CHP Capability Host Endpoint Demo

This demo serves a real `LocalCapabilityHost` over HTTP and then invokes it
through the CHP boundary.

It demonstrates:

- host discovery
- capability invocation
- correlation propagation
- denial evidence
- replay by correlation ID
- evidence-backed explanation
- counterfactual evaluation

Run the end-to-end demo:

```bash
chp demo endpoint
```

Serve the host manually:

```bash
chp serve-demo --port 8765
```

Then call it:

```bash
chp host
chp invoke demo.search_information \
  --payload '{"query":"CHP vs MCP"}' \
  --correlation-id corr_demo
chp replay corr_demo
```

The HTTP surface is intentionally small. CHP v0.1 remains transport-neutral;
this example is one way to serve a host locally.

The raw Python scripts remain available for contributors working directly from
the source tree.
