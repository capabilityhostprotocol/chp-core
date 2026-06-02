# CHP Capability Lookup — Find and Invoke Capabilities

Status: legacy internal mesh lookup prompt.

This document describes older internal fleet and Zenoh-mesh lookup patterns. It
is not required for CHP v0.1 conformance or public launch usage. For the public
v0.1 protocol, start with `spec/chp-v0.1.md`.

Use this prompt to discover what CHP capabilities exist across the fleet and how to invoke them.

## Discover available capabilities

```bash
# What capabilities does a host serve?
chp host                                   # inspect a running local host
chp invoke chp.discovery.list_capabilities # discover via CHP protocol
```

## Invoke a capability from another project

### Direct invocation (same process / shared dependency)

If both projects share `@auxo/capability-serve`:

```typescript
import { invoke } from '@auxo/capability-serve';

// Import the target project's capability definitions
import 'other-project/src/chp/capabilities.js';

// Invoke by name
const result = await invoke('other-project.operation:1.0.0', {
  input: 'some data',
});

console.log(result.data);      // the response
console.log(result.evidence);  // execution_started + execution_completed
console.log(result.success);   // true/false
```

### Cross-project invocation (via Zenoh mesh)

If the target project is serving on the mesh (Tier 2):

```typescript
import { CHPClient } from '@auxo/chp-client';

const client = new CHPClient();

// Discover what's on the mesh
const hosts = await client.discoverHosts();
const caps = await client.discoverCapabilities();
console.log('Available:', caps.map(c => c.name));

// Invoke a remote capability
const result = await client.invoke({
  hostId: 'north-star',
  capabilityId: 'drift.observe.current:1.0.0',
  payload: { portfolio: 'main' },
  context: {
    subject_id: 'z6Mk...',
    entitlements: ['drift.observe:1.0.0'],
  },
});
```

### From Python (via Zenoh transport binding)

```python
import zenoh, json

session = zenoh.open()

# Discover capabilities on a host
replies = session.get("chp/v1/capabilities/north-star/declarations")
for reply in replies:
    data = json.loads(reply.payload)
    for cap in data["capabilities"]:
        print(f"  {cap['name']}:{cap['version']}  risk={cap['risk_class']}")

# Invoke a capability
request = {
    "requestId": f"req-{int(time.time())}",
    "capabilityId": "drift.observe.current",
    "version": "1.0.0",
    "context": {"subject_id": "z6Mk..."},
    "payload": {"portfolio": "main"},
}
replies = session.get(
    "chp/v1/invocations/north-star/requests",
    value=json.dumps(request),
)
for reply in replies:
    result = json.loads(reply.payload)
    print(result["result"]["data"])
```

### From Rust (via Zenoh transport binding)

```rust
use zenoh::prelude::r#async::*;

let session = zenoh::open(config::default()).res().await?;

// Discover
let replies = session.get("chp/v1/capabilities/*/declarations").res().await?;
while let Ok(reply) = replies.recv_async().await {
    let data: serde_json::Value = serde_json::from_slice(reply.sample?.payload.contiguous().as_ref())?;
    println!("{}", data);
}
```

## Capability naming conventions

```
{project}.{module}.{action}:{version}

Examples:
  north-star.drift.observe.current:1.0.0
  automaton.economic.transfer:1.0.0
  demiurge.batch.create:1.0.0
  exo.runtime.start:1.0.0
```

## Risk classes — what to expect

| Risk | Meaning | Entitlement? | Examples |
|------|---------|-------------|----------|
| `low` | Read-only, no side effects | No | health, list, get, status |
| `medium` | Creates/modifies, reversible | Sometimes | create, update, upload |
| `high` | Deletes, financial, auth | Yes | delete, transfer, reset |
| `critical` | Irreversible, multi-system | Always | deploy, sign, attest |

## Check if a specific capability exists

```python
from chp_core import LocalCapabilityHost

host = LocalCapabilityHost()
# ... register capabilities ...
results = host.discover(namespace="drift.")
print([c["id"] for c in results["capabilities"]])
```

## Resources

- Spec: `spec/chp-v0.1.md`
- Quickstart: `docs/quickstart.md`
- JSON Schemas: `schemas/`
