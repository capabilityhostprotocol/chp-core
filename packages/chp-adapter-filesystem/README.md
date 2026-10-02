# chp-adapter-filesystem

**Governed file operations as CHP capabilities — read, write, list, and search, scoped to an
allowlist of roots, with every call admission-gated and recorded as signed, replayable evidence.**

```bash
pip install chp-adapter-filesystem
```

Compose it onto any CHP host, or onto [`chp-server`](https://pypi.org/project/chp-server/):

```python
from chp_server import CapabilityServer
from chp_adapter_filesystem import FilesystemAdapter, FilesystemConfig

app = CapabilityServer("my-host")
app.compose(FilesystemAdapter(FilesystemConfig(
    allowed_roots=["./data"])))          # nothing outside these roots is reachable
app.run(port=8800)
```

## Capabilities

- **`chp.adapters.filesystem.read_file`**, **`write_file`**, **`list_directory`**,
  **`glob_files`**, **`grep`**, **`extract`** — each denied outside `allowed_roots`, each
  replayable at `/replay/{correlation}`.

A path outside the allowlist is denied by the pipeline before the handler runs — the same governance
your own capabilities get, applied to the filesystem.

---

Part of the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core) — one
governed implementation of a capability, consumed everywhere. Apache-2.0.
