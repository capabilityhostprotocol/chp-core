# chp-adapter-http

**A governed HTTP client as CHP capabilities — every outbound request is admission-gated,
origin-allowlisted, and recorded as signed, replayable evidence.**

```bash
pip install chp-adapter-http
```

Compose it onto any CHP host, or onto [`chp-server`](https://pypi.org/project/chp-server/):

```python
from chp_server import CapabilityServer
from chp_adapter_http import HttpAdapter, HttpConfig

app = CapabilityServer("my-host")
app.compose(HttpAdapter(HttpConfig(
    allowed_origins=["https://api.example.com"])))   # sandbox to explicit scheme://host[:port]
app.run(port=8800)
```

## Capabilities

- **`chp.adapters.http.request`** — a governed HTTP request (method, url, headers, body).
- **`chp.adapters.http.stream`** — a streamed response.

Requests are constrained to `allowed_origins`. Header values support `${secret:KEY}` and `${ENV}`
placeholders resolved at call time — so an auth secret never lives in config or evidence — and
request header values and response bodies are kept out of evidence by default.

---

Part of the [Capability Host Protocol](https://github.com/capabilityhostprotocol/chp-core) — one
governed implementation of a capability, consumed everywhere. Apache-2.0.
