# chp-adapter-launchd

Govern macOS **launchd** LaunchAgent services as CHP capabilities. Built so CHP
can manage its own long-running infrastructure (e.g. the TEI and vLLM Metal
servers) — making them persistent across reboot and controllable through the
capability host with a full evidence trail.

## Capabilities

| Capability | Description |
|---|---|
| `chp.adapters.launchd.list` | List CHP-managed services (scoped to the managed prefix). |
| `chp.adapters.launchd.status` | Loaded/running state, pid, last exit code, plist presence. |
| `chp.adapters.launchd.start` | Bootstrap if unloaded, else `kickstart -k` (restart). |
| `chp.adapters.launchd.stop` | Bootout a loaded service. |
| `chp.adapters.launchd.install` | Generate a plist from a spec, write it, and bootstrap. |
| `chp.adapters.launchd.uninstall` | Bootout and remove the plist. |

## Safety

The adapter only manages labels matching `LaunchdConfig.managed_prefix` (default
`com.chp.`) — it will refuse to touch arbitrary system services. `launchctl` and
plist I/O are isolated in `_backends.py`.

## Install a service (example: the TEI server)

```json
{
  "label": "com.chp.tei",
  "program": "/opt/homebrew/bin/text-embeddings-router",
  "args": ["--model-id", "sentence-transformers/all-MiniLM-L6-v2", "--port", "8090"],
  "stdout_path": "/Users/me/.chp/logs/tei.log",
  "stderr_path": "/Users/me/.chp/logs/tei.err",
  "keep_alive": true,
  "run_at_load": true
}
```

## Evidence policy

Emitted: label, operation, pid, returncode, plist path, environment **keys**, latency.
Never emitted: environment variable **values** (may hold tokens) or plist file contents.
