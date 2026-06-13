# Multi-Host Demo

Stands up **two real CHP adapter hosts** over HTTP and points a single
`MultiHostRouter` at both — the smallest end-to-end picture of "working with real
hosts for capabilities."

```
        ┌─────────────────────────────┐
        │       MultiHostRouter        │   merged catalog · routing · stitched replay
        └───────┬──────────────┬──────┘
       HttpTransport     HttpTransport
                │              │
   ┌────────────▼───┐   ┌──────▼───────────┐
   │  cloud-host    │   │   data-host      │
   │  aws,kubernetes│   │ vector,knowledge │
   └────────────────┘   └──────────────────┘
   (own evidence store)  (own evidence store)
```

## Run

```bash
# from the repo root, after dev-install.sh (installs chp-core, chp-host, adapters)
python examples/multi-host-demo/demo.py
```

## What it shows

1. **Real hosts** — each host is a `LocalCapabilityHost` built from named installed
   adapters (`build_adapter_host([...])`) and served over HTTP (`serve_http`).
2. **Merged discovery** — `router.discover()` returns one catalog (26 capabilities),
   each annotated with the host(s) that serve it.
3. **Routing** — `router.ainvoke("chp.adapters.aws.s3_list", ...)` is dispatched to
   `cloud-host`; `chp.adapters.vector.add` to `data-host`. The caller never names a host.
4. **Stitched replay** — both invocations share one correlation; `router.replay(corr)`
   fans out to both hosts and merges their (independent, hash-chained) evidence into one
   ordered, host-tagged timeline.

## Stand the hosts up yourself

The same hosts the demo runs in-process can be launched as standalone processes:

```bash
chp-host serve --adapters aws,kubernetes        --host-id cloud-host --port 8801
chp-host serve --adapters vector,knowledge-graph --host-id data-host  --port 8802
```

…then build a router from `HttpTransport("http://127.0.0.1:8801")` and
`HttpTransport("http://127.0.0.1:8802")`.
