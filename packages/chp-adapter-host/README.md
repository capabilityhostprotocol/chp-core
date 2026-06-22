# chp-adapter-host

Report and update the CHP runtime on a node, as governed capabilities.

- `chp.adapters.host.version` — this node's chp-host version, platform, and installed adapters.
- `chp.adapters.host.update` — schedule a detached `chp-host update --restart` (upgrade CHP packages, then restart the node's services). Returns immediately with `scheduled: true`; the host restarts shortly after, so re-check `/health` for the new `host_version`.

Both emit evidence. `update` is `risk: high` (remote code update + restart) and is gated by the host's API key like any other capability. The primary drives a worker's update over the mesh with `chp-host mesh update <url>`.
