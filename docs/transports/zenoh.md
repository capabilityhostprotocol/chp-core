# CHP-over-Zenoh Transport Binding

Status: legacy mesh draft

This document describes an experimental CHP-over-Zenoh transport binding used by the existing TypeScript mesh work. It is not the CHP v0.1 core protocol specification.

For the open-source launch protocol, see `spec/chp-v0.1.md`. The v0.1 core is transport-agnostic and local-first; Zenoh is one possible transport binding for later multi-host discovery, invocation, and evidence streaming.

Any language (Rust, Swift, Go, Python, TypeScript) can implement this binding to participate in a CHP mesh, but v0.1 conformance does not require Zenoh.

## Key Expression Patterns

All keys use the prefix `chp/v1` by default (configurable per host).

| Key Pattern | Zenoh Primitive | Direction | Purpose |
|-------------|----------------|-----------|---------|
| `chp/v1/capabilities/{host_id}/declarations` | Queryable | Host → Querier | Capability discovery |
| `chp/v1/capabilities/{host_id}/liveliness` | Liveliness Token | Host → Mesh | Peer presence |
| `chp/v1/capabilities/*/declarations` | Get (wildcard) | Querier → All Hosts | Discover all capabilities |
| `chp/v1/capabilities/*/liveliness` | Liveliness Subscribe | Observer → Mesh | Watch for hosts joining/leaving |
| `chp/v1/invocations/{host_id}/requests` | Queryable | Caller → Host | Invoke a capability |
| `chp/v1/evidence/{capability_id}/stream` | Put/Subscribe | Host → Mesh | Broadcast evidence |

## Message Formats

All payloads are UTF-8 JSON strings.

### Capability Discovery Response

Returned when a querier sends `get("chp/v1/capabilities/{host_id}/declarations")`.

```json
{
  "host": {
    "host_id": "production-host",
    "host_type": "chp-host"
  },
  "capabilities": [
    {
      "name": "myapp.users.list",
      "version": "1.0.0",
      "description": "List all users",
      "risk_class": "low",
      "minimum_tier": "S1",
      "require_entitlement": false,
      "owner": "myapp",
      "tags": ["users", "read"],
      "evidence_types": ["execution_started", "execution_completed"],
      "invariants": []
    }
  ],
  "timestamp": "2026-03-27T22:00:00.000Z"
}
```

### Invocation Request

Sent as payload of `get("chp/v1/invocations/{host_id}/requests")`.

```json
{
  "requestId": "req-abc123",
  "capabilityId": "myapp.users.list",
  "version": "1.0.0",
  "context": {
    "subject_id": "z6MkuyYx...",
    "tenant_id": "default",
    "environment": "production",
    "governance_mode": "enforce",
    "entitlements": ["myapp.users.read"],
    "correlation_id": "corr-xyz789"
  },
  "payload": {
    "filter": "active",
    "limit": 50
  },
  "timestamp": "2026-03-27T22:00:01.000Z"
}
```

### Invocation Response

Returned as reply to the invocation query.

```json
{
  "requestId": "req-abc123",
  "result": {
    "success": true,
    "data": { "users": [...] },
    "evidence": [
      {
        "evidence_type": "execution_completed",
        "capability_id": "myapp.users.list:1.0.0",
        "timestamp": "2026-03-27T22:00:01.050Z",
        "subject_id": "z6MkuyYx...",
        "payload": { "duration_ms": 50, "record_count": 42 }
      }
    ]
  },
  "hostId": "production-host",
  "timestamp": "2026-03-27T22:00:01.050Z"
}
```

### Evidence Broadcast

Published via `put("chp/v1/evidence/{capability_id}/stream", evidence_json)`.

```json
{
  "evidence_type": "execution_completed",
  "capability_id": "myapp.users.list:1.0.0",
  "timestamp": "2026-03-27T22:00:01.050Z",
  "subject_id": "z6MkuyYx...",
  "correlation_id": "corr-xyz789",
  "host_id": "production-host",
  "payload": {
    "duration_ms": 50,
    "success": true
  }
}
```

## Enumerations

### RiskClass
`"low"` | `"medium"` | `"high"` | `"critical"`

### AssuranceTier
`"S1"` | `"S2"` | `"S3"`

### GovernanceMode
`"enforce"` | `"audit"` | `"disabled"` | `"shadow"`

### EvidenceType
`"execution_started"` | `"execution_completed"` | `"execution_failed"` | `"execution_denied"` | `"entitlement_checked"` | `"invariant_validated"` | `"invariant_violated"` | `"governance_decision"` | `"lineage_traced"`

## Connection

Default Zenoh endpoints (tried in order):
1. `ws://127.0.0.1:10000` (WebSocket)
2. `tcp://127.0.0.1:7447` (TCP)

Override with `ZENOH_CONNECT` or `CHP_ZENOH_URL` environment variables.

## Identity

CHP subject IDs use the Radicle NID format: `z6Mk...` (Ed25519 public key in multibase/multicodec). One Ed25519 seed derives:
- **Radicle NID** — repository identity
- **CHP subject_id** — capability invocation identity
- **AUXO address** — `0x` + SHA-256(pubkey)[:20]

## Implementing in Rust

```rust
use zenoh::prelude::r#async::*;

// 1. Open session
let session = zenoh::open(config::default()).res().await?;

// 2. Declare capability queryable
let queryable = session
    .declare_queryable("chp/v1/capabilities/my-host/declarations")
    .res().await?;

// 3. Handle queries
while let Ok(query) = queryable.recv_async().await {
    let response = serde_json::json!({
        "host": { "host_id": "my-host" },
        "capabilities": [{ "name": "my.cap", "version": "1.0.0", "risk_class": "low" }],
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    query.reply(Ok(Sample::new(
        query.key_expr().clone(),
        response.to_string(),
    ))).res().await?;
}
```

## Implementing in Python

```python
import zenoh, json

session = zenoh.open()

# Declare capability queryable
def handle_query(query):
    response = {
        "host": {"host_id": "my-host"},
        "capabilities": [{"name": "my.cap", "version": "1.0.0", "risk_class": "low"}],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    query.reply(zenoh.Sample(query.key_expr, json.dumps(response)))

queryable = session.declare_queryable("chp/v1/capabilities/my-host/declarations", handle_query)
```
