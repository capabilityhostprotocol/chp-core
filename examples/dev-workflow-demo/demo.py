"""Dev-workflow demo: CHP used to develop CHP.

Stands up a **dev-host** serving the five engineering-loop adapters:
  git · github · radicle · process · container

Then uses a MultiHostRouter to:
  1. Discover the full dev-loop capability catalog.
  2. Run a three-step dogfood sequence under one correlation:
       a. chp.adapters.git.status        — inspect the chp-dev working tree
       b. chp.adapters.radicle.repo_info — get the Radicle RID of chp-dev
       c. chp.adapters.process.run       — run the chp-host test suite (fast)
  3. Replay the stitched evidence timeline for that correlation.

Run it:  python demo.py
Needs:   pip install -e chp-core/packages/python  chp-dev/packages/chp-host
         plus chp-adapter-git/-github/-radicle/-process/-container
"""

from __future__ import annotations

import asyncio
import os
import threading
import time

from chp_core import HttpTransport, create_http_server
from chp_host import MultiHostRouter, build_adapter_host

# chp-dev repo root — resolve relative to this file
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEV_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_AGENT_ROOT = os.path.abspath(os.path.join(_DEV_ROOT, "..", "chp-agent"))

_DEV_ADAPTERS = ["git", "github", "radicle", "process", "container"]


def _serve(adapters: list[str], host_id: str) -> tuple[str, object]:
    """Build a dev-host and serve it on an ephemeral port; return (url, server)."""
    host, result = build_adapter_host(adapters, host_id=host_id, store_path=":memory:")
    server = create_http_server(host, bind="127.0.0.1", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    registered = result.registered
    skipped = result.skipped
    print(f"  {host_id:<14} :{port}  registered={registered}  skipped={skipped}")
    return f"http://127.0.0.1:{port}", server


async def main() -> None:
    print("=" * 60)
    print("CHP dev-workflow demo — CHP used to develop CHP")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # 1. Start dev-host                                                   #
    # ------------------------------------------------------------------ #
    print("\nStarting dev-host:")
    dev_url, dev_srv = _serve(_DEV_ADAPTERS, "chp-dev-host")
    time.sleep(0.25)

    router = MultiHostRouter([HttpTransport(dev_url, name="chp-dev-host")])
    await router.connect()

    # ------------------------------------------------------------------ #
    # 2. Discover                                                         #
    # ------------------------------------------------------------------ #
    catalog = await router.discover()
    cap_count = catalog["capability_count"]
    print(f"\nDiscovered {cap_count} capabilities on chp-dev-host.")
    print("  Dev-loop capabilities present:")
    dev_loop_ids = sorted(
        c["id"] for c in catalog["capabilities"]
        if any(tag in c["id"] for tag in ("git", "radicle", "process", "container", "github"))
    )
    for cid in dev_loop_ids[:10]:
        print(f"    {cid}")
    if len(dev_loop_ids) > 10:
        print(f"    … and {len(dev_loop_ids) - 10} more")

    # ------------------------------------------------------------------ #
    # 3. Three-step dogfood sequence under one correlation                #
    # ------------------------------------------------------------------ #
    corr = {"correlation_id": "dev-dogfood-demo"}
    print(f"\nRunning 3-step dogfood sequence (correlation: {corr['correlation_id']}):")

    # a. Git status of chp-dev
    r_git = await router.ainvoke(
        "chp.adapters.git.status",
        {"repo_path": _DEV_ROOT},
        correlation=corr,
    )
    if r_git.outcome == "success":
        d = r_git.data
        print(f"  git.status     → branch={d.get('branch','?')}  "
              f"staged={d.get('staged',0)}  unstaged={d.get('unstaged',0)}  "
              f"clean={d.get('clean',False)}")
    else:
        print(f"  git.status     → {r_git.outcome}")

    # b. Radicle repo info for chp-dev
    r_rad = await router.ainvoke(
        "chp.adapters.radicle.repo_info",
        {"repo_path": _DEV_ROOT},
        correlation=corr,
    )
    if r_rad.outcome == "success":
        d = r_rad.data
        print(f"  radicle.info   → name={d.get('name','?')}  rid={d.get('rid','?')}")
    else:
        print(f"  radicle.info   → {r_rad.outcome}")

    # c. Run chp-host tests (fast, no-cov)
    r_proc = await router.ainvoke(
        "chp.adapters.process.run",
        {
            "command": "python",
            "args": ["-m", "pytest", "packages/chp-host/tests/", "-q", "-o", "addopts=", "--no-header"],
            "cwd": _DEV_ROOT,
            "timeout": 60,
        },
        correlation=corr,
    )
    if r_proc.outcome == "success":
        d = r_proc.data
        print(f"  process.run    → exit={d.get('exit_code','?')}  "
              f"(pytest chp-host: {'PASS' if d.get('exit_code') == 0 else 'FAIL'})")
    else:
        print(f"  process.run    → {r_proc.outcome}")

    # ------------------------------------------------------------------ #
    # 4. Stitched evidence replay                                         #
    # ------------------------------------------------------------------ #
    events = await router.replay("dev-dogfood-demo")
    print(f"\nStitched evidence replay ({len(events)} events):")
    for e in events:
        cap = e.get("capability_id") or e.get("payload", {}).get("capability_id", "")
        etype = e.get("event_type", "?")
        host_tag = e.get("_host", "chp-dev-host")
        print(f"  [{host_tag:<14}] {etype:<28} {cap}")

    # ------------------------------------------------------------------ #
    # 5. Health                                                           #
    # ------------------------------------------------------------------ #
    health = await router.health()
    print(f"\nRouter health: {health['status']} ({health['healthy_count']}/{health['host_count']} hosts up)")

    dev_srv.shutdown()
    dev_srv.server_close()
    print("\nStopped dev-host. Demo complete.")
    print(
        "\nTo run this host persistently:\n"
        f"  chp-host serve --profile {_DEV_ROOT}/profiles/dev-host.json\n"
        "\nThen point the agent at it:\n"
        "  CHP_REMOTE_HOSTS=http://localhost:8801 chp-agent run 'inspect the chp-dev git status'"
    )


if __name__ == "__main__":
    asyncio.run(main())
