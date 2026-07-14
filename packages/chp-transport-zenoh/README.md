# chp-transport-zenoh

A **Zenoh** transport binding for the Capability Host Protocol — a non-HTTP
query/reply + pub/sub data plane for low-latency mesh invocation and native
evidence streaming.

`ZenohTransport` satisfies the same `chp_core.transport.Transport` protocol the
HTTP transport does, so the CHP router composes it with **zero changes**. The wire
objects are unchanged — the same `InvocationEnvelope` / `InvocationResult` JSON the
HTTP binding carries — only the carrier differs. See
[`spec/chp-zenoh-binding.md`](https://github.com/capabilityhostprotocol/chp-core/blob/main/spec/chp-zenoh-binding.md).

`chp-core` itself stays dependency-free; installing this package is what pulls the
`eclipse-zenoh` dependency.

```python
from chp_core import LocalCapabilityHost, CapabilityDescriptor
from chp_transport_zenoh import ZenohHostServer, ZenohTransport

host = LocalCapabilityHost("agent-a")
host.register(CapabilityDescriptor(id="math.add", version="1.0.0", description="."),
              lambda ctx, p: {"sum": p["a"] + p["b"]})

server = ZenohHostServer(host)                 # declares the queryables over Zenoh
transport = ZenohTransport("agent-a")          # the client side
result = await transport.ainvoke_envelope(...) # same InvocationResult as HTTP
```

Requires a Zenoh 1.x runtime (`pip install eclipse-zenoh`); peers discover each
other via Zenoh scouting, or connect through a `zenohd` router.
