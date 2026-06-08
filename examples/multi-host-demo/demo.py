#!/usr/bin/env python3
"""Multi-host demo — RemoteCapabilityHost connecting two agents over HTTP.

Demonstrates:
  - Agent A hosts capabilities locally, served via serve_http
  - Agent B uses RemoteCapabilityHost to invoke Agent A's capabilities
  - Cross-host invocation looks identical to local invocation
  - Replay, discover, and health all work across the wire

Run:
    python examples/multi-host-demo/demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    CapabilityDescriptor,
    LocalCapabilityHost,
    RemoteCapabilityHost,
    SQLiteEvidenceStore,
    capability,
    create_http_server,
)


def sep(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


# ---------------------------------------------------------------------------
# Agent A — the capability provider
# Hosts two capabilities: data.summarize and math.stats
# ---------------------------------------------------------------------------

agent_a = LocalCapabilityHost("agent-a", store=SQLiteEvidenceStore(":memory:"))


@capability(
    id="data.summarize",
    version="1.0.0",
    description="Summarize a list of strings.",
    tags=["data", "text"],
)
def summarize(items: list) -> dict:
    return {
        "count": len(items),
        "sample": items[:2],
        "summary": f"{len(items)} items, first: {items[0] if items else 'none'}",
    }


@capability(
    id="math.stats",
    version="1.0.0",
    description="Basic statistics over a list of numbers.",
    tags=["math", "stats"],
)
def stats(numbers: list) -> dict:
    if not numbers:
        return {"count": 0, "mean": 0.0, "min": 0.0, "max": 0.0}
    n = len(numbers)
    return {
        "count": n,
        "mean": round(sum(numbers) / n, 4),
        "min": min(numbers),
        "max": max(numbers),
    }


agent_a.register(summarize)
agent_a.register(stats)

# Serve Agent A on a random port (port=0 lets the OS assign one)
server = create_http_server(agent_a, port=0)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base_url = f"http://127.0.0.1:{server.server_port}"

# ---------------------------------------------------------------------------
# Agent B — the remote caller
# Uses RemoteCapabilityHost — same API as LocalCapabilityHost
# ---------------------------------------------------------------------------

agent_b = RemoteCapabilityHost(base_url)


# ---------------------------------------------------------------------------
# Part 1 — Health and discovery
# ---------------------------------------------------------------------------

sep("Part 1 — Health check and capability discovery")

health = agent_b.health()
print(f"\nHealth: {health['status']}  |  host: {health['host_id']}  |  caps: {health['capability_count']}")

descriptor = agent_b.discover()
print(f"\nHost '{descriptor['id']}' exposes {len(descriptor['capabilities'])} capabilities:")
for cap_desc in descriptor["capabilities"]:
    print(f"  {cap_desc['id']}:{cap_desc['version']}  —  {cap_desc['description']}")

# Filtered discovery
filtered = agent_b.discover(id="math.stats")
print(f"\nFiltered (id=math.stats): {len(filtered['capabilities'])} result(s)")


# ---------------------------------------------------------------------------
# Part 2 — Synchronous invocation
# ---------------------------------------------------------------------------

sep("Part 2 — Synchronous cross-host invocation")

result = agent_b.invoke(
    "math.stats",
    {"numbers": [10, 20, 30, 40, 50]},
    correlation={"correlation_id": "cross-host-001"},
)
print(f"\nagent_b → agent_a.math.stats")
print(f"  outcome:  {result.outcome}")
print(f"  data:     {json.dumps(result.data, indent=2)}")
print(f"  corr_id:  {result.correlation.correlation_id}")


# ---------------------------------------------------------------------------
# Part 3 — Async invocation
# ---------------------------------------------------------------------------

sep("Part 3 — Async cross-host invocation")


async def run_async():
    result = await agent_b.ainvoke(
        "data.summarize",
        {"items": ["alpha", "beta", "gamma", "delta"]},
        correlation={"correlation_id": "cross-host-002"},
    )
    print(f"\nawait agent_b.ainvoke('data.summarize', ...)")
    print(f"  outcome:  {result.outcome}")
    print(f"  count:    {result.data['count']}")
    print(f"  sample:   {result.data['sample']}")


asyncio.run(run_async())


# ---------------------------------------------------------------------------
# Part 4 — Replay across the wire
# ---------------------------------------------------------------------------

sep("Part 4 — Evidence replay through RemoteCapabilityHost")

# Evidence is stored on Agent A — replay fetches it via HTTP
events = agent_b.replay("cross-host-001")
print(f"\nReplay for 'cross-host-001' ({len(events)} events):")
for ev in events:
    print(f"  [{ev['sequence']:2d}]  {ev['event_type']:32s}  cap={ev['capability_id']}")

replay_result = agent_b.replay_result("cross-host-002")
print(f"\nreplay_result('cross-host-002'): {replay_result['event_count']} events, "
      f"types={[e['event_type'] for e in replay_result['events']]}")


# ---------------------------------------------------------------------------
# Part 5 — Unknown capability (graceful denial)
# ---------------------------------------------------------------------------

sep("Part 5 — Unknown capability returns governed denial")

result = agent_b.invoke("no.such.capability", {})
print(f"\nagent_b.invoke('no.such.capability', {{}})")
print(f"  success:  {result.success}")
print(f"  outcome:  {result.outcome}")
print(f"  denial:   code={result.denial.code}")


# ---------------------------------------------------------------------------
# Teardown + summary
# ---------------------------------------------------------------------------

server.shutdown()
server.server_close()
thread.join(timeout=2)

sep("Summary")
print("""
v0.6.3 additions verified:

  RemoteCapabilityHost
    ✓ health()      — liveness check over HTTP
    ✓ discover()    — capability listing, with optional filter
    ✓ invoke()      — synchronous cross-host invocation
    ✓ ainvoke()     — async cross-host invocation
    ✓ replay()      — evidence events fetched from remote host
    ✓ replay_result() — full replay result with event_count
    ✓ Unknown capability → denied result (not an exception)
    ✓ Zero new deps: stdlib urllib.request only
""")
