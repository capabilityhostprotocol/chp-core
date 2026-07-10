# CHP Mesh Conformance — Fixture Profile

Status: normative for the `mesh` suite. This is the language-agnostic contract
for proving a **routing intermediary** (a gateway) satisfies the
routing-intermediary obligations of [chp-v0.2.md §11](../spec/chp-v0.2.md)
(reachability as governed evidence) and §10 "Forwarding" (mandate
passthrough), plus [chp-http-binding.md §3](../spec/chp-http-binding.md).

## Topology

The runner hosts the **members**; you host the **gateway**:

```
runner ──drives──▶ GATEWAY-UNDER-TEST ──routes──▶ member-a (runner's, port 8951)
                        (yours)        └────────▶ member-b (runner's, port 8952)
```

The runner spawns two reference member hosts and induces failure by killing
its own member — the suite never needs control of your implementation.
Member capabilities: `member-a` serves `mesh.echo` + `mesh.only-a`;
`member-b` serves `mesh.echo` (so failover and sole-owner unreachability are
both exercisable).

## Gateway configuration

Point your gateway at the runner's members — for the reference implementation
that is a manifest like:

```json
{
  "name": "mesh-conformance",
  "agent_remotes": [
    {"url": "http://127.0.0.1:8951"},
    {"url": "http://127.0.0.1:8952"}
  ],
  "gateway": {"port": 8953, "bind": "127.0.0.1",
              "host_id": "gateway-under-test",
              "store": "/tmp/mesh-gateway.sqlite"}
}
```

- The members are **keyless** — the gateway must reach them without
  credentials (the runner clears ambient `CHP_HOST_API_KEY[S]` before
  serving them). If YOUR gateway requires auth from callers, pass its key to
  the runner via `--key`.
- **An evidence store is a fixture-profile requirement** (the same way the
  wire profile requires a safety evaluator): the suite asserts the gateway's
  own §11 events merge into stitched replays. A storeless router remains
  spec-conformant at the returned-denial floor, but the mesh suite does not
  certify it.
- **Start order is a MUST**: members first (start the runner — it binds them
  and waits), *then* your gateway (it discovers its routing table at boot).

## The checks (ordered — the suite is stateful; destructive checks last)

| # | Check | Obligation |
|---|---|---|
| 1 | merged discovery | gateway `/host` merges both members' catalogs, `mesh.echo` annotated with both owners |
| 2 | routed invocation | success routed to an owner; the **caller's correlation** appears in the member's evidence |
| 3 | mandate forwarded unchanged | a mandate presented at the gateway (never-met principal) yields the delegate-under-principal subject in the **member's** chain (§10 Forwarding) |
| 4 | export assembles | `/export/{corr}` returns a cross-host task bundle that verifies (hash-chain tier suffices) with both members contributing |
| 5 | failover | member-a is killed; `mesh.echo` still succeeds via member-b |
| 6 | `host_unreachable` | `mesh.only-a` → HTTP **200**, outcome `denied`, reserved code `host_unreachable`, `retryable: true`, `details.attempted_hosts` non-empty — never a bare 5xx |
| 7 | partial replay disclosed | `/replay/{corr}` → `partial: true` + `missing_hosts` (entries are **transport URLs**, not host_ids) + the gateway's own `host_marked_unhealthy` merged into the timeline |
| 8 | export refuses partial | `/export/{corr}` → `503` naming the unreachable member |

## Running the check

```
python conformance/runner.py --gateway-url http://127.0.0.1:PORT --suite mesh
<start your gateway once the members are up>
```

A conforming intermediary prints `[mesh] 8/8`. Custom member ports:
`--member-ports 9001,9002` (update your gateway config to match). The
reference implementation's continuous proof lives at
`packages/chp-host/tests/test_mesh_conformance.py`.
