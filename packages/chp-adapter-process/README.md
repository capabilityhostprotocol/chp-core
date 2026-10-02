# chp-adapter-process

**Governed shell execution as a CHP capability — commands are policy-gated (an allowlist plus
optional human approval) and every run is recorded as signed, replayable evidence.**

```bash
pip install chp-adapter-process
```

Compose it onto any CHP host, or onto [`chp-server`](https://pypi.org/project/chp-server/):

```python
from chp_server import CapabilityServer
from chp_adapter_process import ProcessAdapter, ProcessConfig

app = CapabilityServer("automation")
app.compose(ProcessAdapter(ProcessConfig(
    allowed_commands=["git", "ls", "cat"])))   # scope exactly what may run
app.run(port=8800)
```

## Capability

- **`chp.adapters.process.run`** — run a command constrained to `allowed_commands`, with
  `working_dir` and `max_timeout`. The pipeline can require **human approval** before it executes;
  the command and its outcome are evidenced. Automation you can hand to an agent.

---

Part of the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core) — one
governed implementation of a capability, consumed everywhere. Apache-2.0.
