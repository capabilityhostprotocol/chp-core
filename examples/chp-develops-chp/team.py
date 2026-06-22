#!/usr/bin/env python3
"""A team of agents contributing to CHP, together, over the mesh.

Multiple coder agents — each backed by a different model on a different node
(e.g. Qwen3-14B on the primary, Qwen3-4B on the inference node) — pull from one
task backlog and work in parallel-of-people (round-robin assignment). They share
ONE correlation id, so the whole collaborative session is a single replayable
evidence trail. scout (FastContext) is the shared code-locator each coder calls.

    export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
    # propose-only (safe) across the default roster:
    python team.py "Add a docstring to X" "Tighten the type hint in Y"
    # apply on a branch:
    python team.py --apply "task one" "task two"

Tasks may be "instruction" or "path::instruction" to pin the target file.
Read-only/propose by default; --apply writes (run on a branch). Never pushes.
"""

from __future__ import annotations

import argparse
import os

from coder import CoderAgent, DEFAULT_REPO
from mesh_lib import MeshClient

# The roster: who's on the team, which model, which node. Add rows as the fleet
# grows (more nodes/models = more contributors).
ROSTER = [
    {"name": "primary-coder", "model": "mlx-community/Qwen3-14B-4bit", "prefer": "primary"},
    {"name": "edge-coder", "model": "mlx-community/Qwen3-4B-Instruct-2507-4bit", "prefer": "inference"},
]


def main() -> int:
    ap = argparse.ArgumentParser(description="A team of CHP coding agents on the mesh.")
    ap.add_argument("tasks", nargs="+", help='Tasks. Use "path::instruction" to pin a file.')
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--apply", action="store_true", help="Write changes (default: propose only).")
    ap.add_argument("--solo", help="Restrict to one roster member by name (e.g. primary-coder).")
    args = ap.parse_args()

    roster = [r for r in ROSTER if (not args.solo or r["name"] == args.solo)]
    if not roster:
        print(f"No roster member named {args.solo!r}. Have: {[r['name'] for r in ROSTER]}")
        return 2

    # One shared client → one correlation id for the whole team session.
    client = MeshClient()
    agents = [CoderAgent(client, args.repo, r["model"], r["prefer"], name=r["name"]) for r in roster]
    print(f"CHP agent team · {len(agents)} contributors · correlation={client.correlation['correlation_id']}")
    for a in agents:
        print(f"  • {a.name}: {a.model} @{a.prefer}")
    print(f"  mode: {'APPLY' if args.apply else 'propose-only'} · {len(args.tasks)} task(s)\n")

    results = []
    for i, raw in enumerate(args.tasks):
        target, _, task = raw.partition("::")
        if not task:  # no "path::" prefix → scout locates the file
            target, task = None, raw
        agent = agents[i % len(agents)]  # round-robin assignment
        print(f"--- task {i + 1}/{len(args.tasks)} → {agent.name} ---")
        results.append(agent.run(task, target, args.apply))
        print()

    print("=" * 70 + "\nTEAM SUMMARY\n" + "=" * 70)
    for r in results:
        extra = r.get("conformance") or r.get("preview") or r.get("note") or r.get("error") or ""
        print(f"  [{r.get('agent'):14}] {r.get('status'):18} {r.get('target') or '-'}  {str(extra)[:50]}")
    client.print_trail()
    print("\nReplay the whole team session via the correlation id (router.replay / mesh audit).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
