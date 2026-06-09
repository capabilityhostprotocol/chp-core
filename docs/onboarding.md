# CHP Onboarding Guide

Status: legacy. This document describes pre-v0.1 Zenoh-mesh adoption patterns that are no longer in use.

Start here instead:
- `README.md` — protocol overview and quick start
- `docs/adopter-quickstart.md` — 10-minute path to first evidence event
- `spec/chp-v0.1.md` — normative protocol specification
- `AGENTS.md` — orientation for AI agents working in this repo

How to adopt the Capability Host Protocol in your project. Self-serve — pick your language, follow the path.

## What You Get

By adopting CHP, your project's operations become:
- **Governed** — risk classification, entitlements, assurance tiers on every invocation
- **Observable** — automatic evidence emission (started, completed, failed, denied)
- **Discoverable** — other CHP hosts can find and invoke your capabilities across the mesh
- **Composable** — capabilities from any host can be chained into workflows
- **Identity-aware** — `subject_id` in `CorrelationContext` carries caller identity into every evidence event

## Choose Your Path

| Your Project | Language | Path | Time to First Capability |
|-------------|----------|------|--------------------------|
| TypeScript/Node.js | TS/JS | [Path A: npm install](#path-a-typescript) | 30 min |
| Python | Python | [Path B: Python SDK](#path-b-python) | 1 hour |
| Rust | Rust | [Path C: Zenoh Transport](#path-c-rust) | 2-3 hours |
| Swift | Swift | [Path D: Zenoh Transport](#path-d-swift) | 2-3 hours |
| Other | Any | [Path C/D adapted](#path-c-rust) | 2-3 hours |

---

## Path A: TypeScript

### Step 1 — Install (30 seconds)

```bash
npm install @auxo/capability-serve
```

No native dependencies. No Zenoh required for development.

### Step 2 — Define Your First Capability (5 minutes)

Create `src/chp/capabilities.ts`:

```typescript
import { defineCapability } from '@auxo/capability-serve';

// Wrap any existing function as a governed capability
export const myCapability = defineCapability(
  {
    name: 'myproject.operation.name',    // dot-separated namespace
    version: '1.0.0',
    description: 'What this operation does',
    risk_class: 'low',                   // low | medium | high | critical
  },
  async (_ctx, payload: { input: string }) => {
    // Your existing logic here
    const result = await yourExistingFunction(payload.input);
    return { success: true, data: result };
  }
);
```

### Step 3 — Serve (2 minutes)

Create `src/chp/serve.ts`:

```typescript
import { serve } from '@auxo/capability-serve';
import './capabilities.js';  // registers capabilities on import

await serve({ hostId: 'myproject', allowMock: true });
console.log('CHP host running');
```

### Step 4 — Graduate to Governance (when ready)

Add entitlements and enforcement:

```typescript
defineCapability({
  name: 'myproject.admin.reset',
  version: '1.0.0',
  risk_class: 'high',
  require_entitlement: true,          // checks ctx.subject entitlements
  enforcement_mode: 'enforce',         // enforce | audit | disabled
  minimum_tier: 'S2',                 // minimum assurance tier
  evidence_types: ['execution_started', 'execution_completed'],
}, async (ctx, payload) => {
  // ctx.subject.subject_id identifies the caller
  // ctx.subject.entitlements is checked automatically
  return { success: true, data: { reset: true } };
});
```

### Step 5 — Join the Mesh (when ready)

Remove `allowMock` to connect to the Zenoh mesh:

```bash
npm install @eclipse-zenoh/zenoh-ts  # add Zenoh client
```

```typescript
await serve({ hostId: 'myproject' });
// Auto-discovers Zenoh at ws://127.0.0.1:10000
// Other CHP hosts can now discover and invoke your capabilities
```

### Type-Only Usage

If you only need CHP types (no capabilities, no serve):

```typescript
import type {
  Evidence,
  RiskClass,
  CapabilityDeclaration,
  AssuranceTier,
} from '@auxo/capability-host-framework/types';
```

### Testing

```typescript
import { MockZenohSession } from '@auxo/capability-host-framework/testing';

// Use in tests — no Zenoh infrastructure needed
// Set CHP_MOCK=1 env var for CI pipelines
```

---

## Path B: Python

### Option B1 — Via auxo-agents SDK (if your project uses auxo-agents)

```python
from auxo_agents.chp.capability import capability, RiskClass
from auxo_agents.chp.context import GovernedContext
from auxo_agents.chp.evidence import EvidenceEmitter

@capability(
    name="myproject.operation.name",
    version="1.0.0",
    risk_class=RiskClass.LOW,
)
async def my_operation(ctx: GovernedContext, payload: dict) -> dict:
    result = await your_existing_function(payload["input"])
    return {"success": True, "data": result}
```

### Option B2 — Direct Zenoh (no TypeScript dependency)

Use the legacy Zenoh transport binding directly with the Python zenoh client:

```bash
pip install eclipse-zenoh
```

```python
import zenoh
import json
from datetime import datetime, timezone

session = zenoh.open()

# Register your capabilities
CAPABILITIES = [{
    "name": "myproject.operation.name",
    "version": "1.0.0",
    "description": "What this operation does",
    "risk_class": "low",
}]

# Handle discovery queries
def handle_discovery(query):
    response = {
        "host": {"host_id": "myproject"},
        "capabilities": CAPABILITIES,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    query.reply(zenoh.Sample(query.key_expr, json.dumps(response)))

queryable = session.declare_queryable(
    "chp/v1/capabilities/myproject/declarations",
    handle_discovery,
)

# Handle invocation queries
def handle_invocation(query):
    request = json.loads(query.payload)
    cap_id = request["capabilityId"]

    # Route to your handler
    result = dispatch_to_handler(cap_id, request["payload"], request["context"])

    response = {
        "requestId": request["requestId"],
        "result": {"success": True, "data": result},
        "hostId": "myproject",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    query.reply(zenoh.Sample(query.key_expr, json.dumps(response)))

invocation_queryable = session.declare_queryable(
    "chp/v1/invocations/myproject/requests",
    handle_invocation,
)

# Emit evidence
def emit_evidence(evidence_type, capability_id, payload):
    evidence = {
        "evidence_type": evidence_type,
        "capability_id": capability_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": "myproject",
        "payload": payload,
    }
    session.put(
        f"chp/v1/evidence/{capability_id}/stream",
        json.dumps(evidence),
    )
```

---

## Path C: Rust

Use the Zenoh transport binding with the native zenoh crate. See `docs/transports/zenoh.md` for the legacy mesh draft. For the v0.1 core protocol, see `spec/chp-v0.1.md`.

### Step 1 — Add dependencies

```toml
[dependencies]
zenoh = "1.0"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = "0.4"
```

### Step 2 — Define types from JSON Schema

Use `packages/capability-host-framework/schema/chp-protocol.schema.json` to generate Rust structs, or define them manually:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RiskClass { Low, Medium, High, Critical }

#[derive(Serialize, Deserialize)]
struct CapabilityDeclaration {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    risk_class: RiskClass,
    // ... see schema for full definition
}

#[derive(Serialize, Deserialize)]
struct DiscoveryResponse {
    host: HostInfo,
    capabilities: Vec<CapabilityDeclaration>,
    timestamp: String,
}
```

### Step 3 — Implement host

```rust
use zenoh::prelude::r#async::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = zenoh::open(config::default()).res().await?;

    // Declare capability discovery
    let queryable = session
        .declare_queryable("chp/v1/capabilities/myproject/declarations")
        .res().await?;

    // Declare liveliness token (peer presence)
    let _token = session
        .liveliness()
        .declare_token("chp/v1/capabilities/myproject/liveliness")
        .res().await?;

    // Handle discovery + invocation queries
    loop {
        tokio::select! {
            Ok(query) = queryable.recv_async() => {
                let response = build_discovery_response();
                query.reply(Ok(Sample::new(
                    query.key_expr().clone(),
                    serde_json::to_string(&response)?,
                ))).res().await?;
            }
        }
    }
}
```

---

## Path D: Swift

Similar to Rust — use the Zenoh Swift client with the transport binding.

```swift
import Zenoh

let session = try await Zenoh.open()

// Declare capability queryable
let queryable = try await session.declareQueryable(
    keyExpr: "chp/v1/capabilities/myproject/declarations"
)

// Handle queries
for try await query in queryable {
    let response = DiscoveryResponse(
        host: HostInfo(hostId: "myproject"),
        capabilities: myCapabilities,
        timestamp: ISO8601DateFormatter().string(from: Date())
    )
    try await query.reply(
        keyExpr: query.keyExpr,
        payload: JSONEncoder().encode(response)
    )
}
```

---

## Naming Conventions

```
{org}.{domain}.{operation}     e.g., auxo.users.list
{project}.{module}.{action}    e.g., demiurge.batch.create
```

- Use dots for hierarchy
- Lowercase, no spaces
- Version separately: `demiurge.batch.create:1.0.0`

## Risk Classification Guide

| Risk Class | When to Use | Examples |
|-----------|-------------|---------|
| `low` | Read-only, no side effects | list, get, search, status |
| `medium` | Creates/modifies data, reversible | create, update, upload |
| `high` | Deletes data, financial ops, auth changes | delete, transfer, reset |
| `critical` | Irreversible, multi-system, compliance-sensitive | deploy, sign, attest |

## Evidence Types

Automatic evidence (emitted by the CHP wrapper):
- `execution_started` — capability invocation begins
- `execution_completed` — successful completion with timing
- `execution_failed` — error with stack trace
- `execution_denied` — entitlement or governance rejection

Manual evidence (emit from your handler):
- `entitlement_checked` — authorization decision logged
- `invariant_validated` / `invariant_violated` — pre/post condition result
- `governance_decision` — policy engine decision
- `lineage_traced` — data provenance link

## Checklist

- [ ] Pick a namespace (e.g., `myproject.module.action`)
- [ ] Define 1-3 capabilities starting with the most valuable operation
- [ ] Assign risk classes (start with `low` — you can increase later)
- [ ] Run in mock mode (`allowMock: true` or `CHP_MOCK=1`)
- [ ] Write one test using MockZenohSession
- [ ] When ready: remove mock, connect to Zenoh mesh
- [ ] When ready: add entitlements for sensitive operations

## Auto-instrumenting Claude Code

Once `chp-core` is installed, one command wires every Claude Code session:

```bash
chp hooks install --global
```

This writes two entries to `~/.claude/settings.json`:
- **PostToolUse** → `chp hook post-tool` (fires after every tool call)
- **Stop** → `chp hook stop` (fires when the session ends)

Evidence is stored at `.chp/claude-code-sessions.sqlite` in your working directory, falling back to `~/.chp/sessions.sqlite`.

### View sessions

```bash
chp session list                          # recent sessions
chp session show <session_id>             # tools used, failures, files touched
chp session replay <session_id>           # full evidence stream as JSON
```

### Change the store path

```bash
export CHP_HOOK_STORE=/path/to/store.sqlite
```

### Project-scoped hooks

```bash
chp hooks install --project   # writes to .claude/settings.json in cwd
chp hooks status              # verify installation
chp hooks uninstall --global  # remove
```

---

## Resources

- **Zenoh Transport Binding**: `docs/transports/zenoh.md`
- **JSON Schema**: `packages/capability-host-framework/schema/chp-protocol.schema.json`
- **Examples**: `packages/capability-serve/examples/`
- **TypeScript API**: `packages/capability-serve/README.md`
- **Spec**: `spec/chp-v0.1.md`
- **Quickstart**: `docs/quickstart.md`
