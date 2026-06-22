#!/usr/bin/env python3
"""Distributed-fleet demo — one operation, routed across physical machines.

Drives the CHP gateway to run a "fleet roll-call": the same capability is
invoked once per node, pinned to that node with affinity (``prefer``), all under
a single correlation id. Then it replays that correlation across the mesh —
proving the substrate end to end:

  * one merged capability catalog at the gateway,
  * affinity routing that lands each step on the chosen physical node,
  * federated, hash-chained evidence that stitches back together by correlation
    id (each event tagged with the ``_host`` that produced it).

It talks to the gateway through CHP's own client (``RemoteCapabilityHost``) —
the sanctioned transport, not hand-rolled HTTP. No model backend required: it
uses ``chp.adapters.host.version`` (present on every node).

Usage:
    python run_demo.py                         # local gateway + keychain key
    CHP_GATEWAY=http://127.0.0.1:8800 \\
    CHP_NODES=inference,worker,primary python run_demo.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from chp_core import RemoteCapabilityHost

GATEWAY = os.environ.get("CHP_GATEWAY", "http://127.0.0.1:8800")
NODES = [n.strip() for n in os.environ.get("CHP_NODES", "inference,worker,primary").split(",") if n.strip()]


def _api_key() -> str:
    # The gateway authenticates with CHP_HOST_API_KEY; read it from the env or
    # the macOS keychain (never printed).
    key = os.environ.get("CHP_HOST_API_KEY")
    if key:
        return key
    r = subprocess.run(
        ["security", "find-generic-password", "-a", "CHP_HOST_API_KEY", "-s", "com.chp.secrets", "-w"],
        capture_output=True, text=True,
    )
    return r.stdout.strip()


def main() -> int:
    key = _api_key()
    if not key:
        print("ERROR: no CHP_HOST_API_KEY (env or keychain) to auth to the gateway.", file=sys.stderr)
        return 1

    gateway = RemoteCapabilityHost(GATEWAY, api_key=key)
    correlation_id = f"fleet-rollcall-{int(time.time())}"
    print(f"Gateway: {GATEWAY}")
    print(f"Correlation: {correlation_id}\n")

    print(f"{'pinned node':<12} {'outcome':<9} {'host_version':<13} {'adapters':<9} {'platform'}")
    print("-" * 74)
    for node in NODES:
        result = gateway.invoke(
            "chp.adapters.host.version", {},
            metadata={"prefer": node},                       # affinity: run on this node
            correlation={"correlation_id": correlation_id},
        )
        d = result.data or {}
        plat = (d.get("platform", "") or "")[:34]
        print(f"{node:<12} {result.outcome:<9} {str(d.get('host_version','')):<13} "
              f"{len(d.get('adapters', [])):<9} {plat}")

    # Federated evidence: replay the one correlation across every node.
    print(f"\nReplaying correlation {correlation_id!r} across the mesh ...")
    events = gateway.replay(correlation_id)
    hosts: dict[str, int] = {}
    for e in events:
        hosts[e.get("_host", "?")] = hosts.get(e.get("_host", "?"), 0) + 1
    print(f"  {len(events)} evidence events, federated across hosts:")
    for host, n in sorted(hosts.items()):
        print(f"    {host}: {n} events")
    print("\nOne operation, three machines, one replayable evidence trail. ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
