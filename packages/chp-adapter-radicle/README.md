# chp-adapter-radicle

**Sovereign, peer-to-peer git as CHP capabilities — clone, init, issues, patches, and sync over
[Radicle](https://radicle.xyz), every operation admission-gated and recorded as signed, replayable
evidence.**

```bash
pip install chp-adapter-radicle
```

Compose it onto any CHP host, or onto [`chp-server`](https://pypi.org/project/chp-server/):

```python
from chp_server import CapabilityServer
from chp_adapter_radicle import RadicleAdapter, RadicleConfig

app = CapabilityServer("my-host")
app.compose(RadicleAdapter(RadicleConfig(default_repo_path="./myrepo")))
app.run(port=8800)
```

## Capabilities

The Radicle surface as governed capabilities: `chp.adapters.radicle.clone`, `init`, `identity`,
`issue_open` / `issue_close` / `issue_comment`, `patch_open` / `patch_merge` / `patch_show`, `push`,
`sync`, `seed` / `unseed`, `node_status`, and more (`chp-server adapters --verbose` for the full set).

Governed, code-hosting sovereignty: no central forge, every operation evidenced.

---

Part of the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core) — one
governed implementation of a capability, consumed everywhere. Apache-2.0.
