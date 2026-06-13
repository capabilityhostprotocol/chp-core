"""Multi-host demo: two real adapter hosts + one router.

Stands up two differentiated CHP hosts over HTTP —
  * a **cloud** host serving aws + kubernetes
  * a **data**  host serving vector + knowledge-graph
— points a single ``MultiHostRouter`` at both, then:
  1. discovers the merged capability catalog,
  2. routes one invocation to each host (router picks the owner),
  3. runs a **stitched** cross-host replay under a shared correlation.

Run it:  python demo.py
Needs:   pip install -e chp-core/packages/python  chp-dev/packages/chp-host
         plus the chp-adapter-aws/-kubernetes/-vector/-knowledge-graph packages.
"""

from __future__ import annotations

import asyncio
import threading
import time

from chp_core import HttpTransport, create_http_server
from chp_host import MultiHostRouter, build_adapter_host


def _serve(adapters: list[str], host_id: str) -> tuple[str, object]:
    """Build an adapter host and serve it on an ephemeral port; return (url, server)."""
    host, result = build_adapter_host(adapters, host_id=host_id, store_path=":memory:")
    server = create_http_server(host, bind="127.0.0.1", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"  {host_id:<12} :{port}  adapters={result.registered}")
    return f"http://127.0.0.1:{port}", server


async def main() -> None:
    print("Starting hosts:")
    cloud_url, cloud_srv = _serve(["aws", "kubernetes"], "cloud-host")
    data_url, data_srv = _serve(["vector", "knowledge-graph"], "data-host")
    time.sleep(0.25)  # let listeners come up

    router = MultiHostRouter(
        [
            HttpTransport(cloud_url, name="cloud-host"),
            HttpTransport(data_url, name="data-host"),
        ]
    )
    await router.connect()

    # 1. Merged discovery across both hosts
    catalog = await router.discover()
    print(f"\nRouter sees {catalog['capability_count']} capabilities across {catalog['hosts']}")
    print("  e.g.:")
    for cap in sorted(catalog["capabilities"], key=lambda c: c["id"])[:6]:
        print(f"    {cap['id']:<40} @ {cap['hosts']}")

    # 2. Route one invocation to each host under a shared correlation
    corr = {"correlation_id": "demo-cross-host"}
    print("\nRouting invocations (shared correlation 'demo-cross-host'):")

    r_cloud = await router.ainvoke("chp.adapters.aws.s3_list", {"bucket": "demo"}, correlation=corr)
    owner = router.hosts_for("chp.adapters.aws.s3_list")
    print(f"  chp.adapters.aws.s3_list      -> {owner[0]:<11} : {r_cloud.outcome}")

    r_data = await router.ainvoke(
        "chp.adapters.vector.add",
        {"id": "doc-1", "text": "capability host protocol", "metadata": {}},
        correlation=corr,
    )
    owner = router.hosts_for("chp.adapters.vector.add")
    print(f"  chp.adapters.vector.add       -> {owner[0]:<11} : {r_data.outcome}")

    # 3. Stitched cross-host replay
    events = await router.replay("demo-cross-host")
    print(f"\nStitched replay of 'demo-cross-host' — {len(events)} events across both hosts:")
    for e in events:
        print(f"    [{e['_host']:<11}] {e.get('event_type', '?'):<22} {e.get('capability_id', '')}")

    # 4. Aggregate health
    health = await router.health()
    print(f"\nRouter health: {health['status']} ({health['healthy_count']}/{health['host_count']} hosts up)")

    cloud_srv.shutdown(); cloud_srv.server_close()
    data_srv.shutdown(); data_srv.server_close()
    print("\nStopped hosts. Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
