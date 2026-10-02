# chp-adapter-composition

**Define and run multi-capability compositions as CHP capabilities — chain governed capabilities
into one, with the whole run admission-gated and recorded as signed, replayable evidence.**

```bash
pip install chp-adapter-composition
```

Compose it onto any CHP host, or onto [`chp-server`](https://pypi.org/project/chp-server/):

```python
from chp_server import CapabilityServer
from chp_adapter_composition import CompositionAdapter, CompositionConfig

app = CapabilityServer("my-host")
app.compose(CompositionAdapter())
app.run(port=8800)
```

## Capabilities

- **`chp.adapters.composition.define`** — declare a composition of capabilities.
- **`chp.adapters.composition.run`** — run it; each step passes the full pipeline and is evidenced.
- **`chp.adapters.composition.get`** / **`list`** — inspect defined compositions.

A composition is itself a governed capability — the evidence chain spans every step.

---

Part of the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core) — one
governed implementation of a capability, consumed everywhere. Apache-2.0.
