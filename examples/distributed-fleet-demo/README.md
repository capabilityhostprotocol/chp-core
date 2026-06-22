# Distributed-fleet demo

One logical operation, routed across several physical machines, with a single
replayable evidence trail. This is the CHP mesh substrate end to end.

## What it shows

The script runs a **fleet roll-call**: it invokes `chp.adapters.host.version`
once per node through the **gateway**, pinning each call to a specific node with
**affinity** (`metadata.prefer = "<node name or role>"`), all under one
**correlation id**. Then it **replays** that correlation across the mesh.

It demonstrates three properties of the substrate:

1. **One merged catalog** — the gateway exposes every node's capabilities as a
   single surface; the caller doesn't address machines, it addresses
   capabilities.
2. **Affinity routing** — `prefer` lands each call on the chosen node
   (`inference` / `worker` / `primary`). The returned `adapters`/`platform`
   differ per machine, proving the call ran where it was pinned.
3. **Federated evidence** — each node keeps its own append-only, hash-chained
   store. `GET /replay/{correlation_id}` fans out across the fleet and stitches
   the events into one timeline, each tagged with the `_host` that produced it.

## Run it

```bash
# Defaults to the local gateway (http://127.0.0.1:8800) and the keychain key.
python run_demo.py

# Or point it at a specific gateway / set of nodes:
CHP_GATEWAY=http://127.0.0.1:8800 CHP_NODES=inference,worker,primary python run_demo.py
```

Example output:

```
pinned node  outcome   host_version  adapters  platform
--------------------------------------------------------------------------
inference    success   0.8.10        14        macOS-15.5-arm64-arm-64bit
worker       success   0.8.10        10        macOS-15.7.4-arm64-arm-64bit
primary      success   0.8.10        67        macOS-15.7.4-arm64-arm-64bit

Replaying correlation 'fleet-rollcall-...' across the mesh ...
  9 evidence events, federated across hosts:
    http://100.88.171.123:8803: 3 events
    http://100.98.36.92:8803: 3 events
    http://127.0.0.1:8803: 3 events
```

## Notes

- Uses only `chp.adapters.host.version` (present on every node), so no model
  backend is required to run it.
- Affinity is a **soft pin**: if the preferred node is down, the gateway still
  routes to another owner — availability beats affinity.
- The same pattern drives real workloads: pin an embedding/inference step to the
  `inference` node, a write to `storage`, a sensor read to `raspi` — one
  correlation, one replayable trail across the fleet.
