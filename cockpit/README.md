# CHP Cockpit (internal)

A browser cockpit to **drive the CHP mesh with an agent** — forked from the
OpenHarness `nextjs-demo`. The agent's tools are governed mesh capabilities
(over the HTTP/SSE MCP transport), every tool call is risk-assessed by
`chp.adapters.safety.assess`, and the model runs on a node (not this host).

> **Internal / non-public.** Bind everything to Tailscale + auth. This is **not**
> part of `chp-site` and must never be deployed publicly or show live mesh/node
> counts.

## Architecture

```
browser ──▶ /api/chat (Next route) ──▶ OpenHarness Agent
                                          ├─ tools: CHP mesh via SSE MCP  (chp-host mcp --http)
                                          ├─ approve: chp.adapters.safety.assess  (gates high-risk)
                                          └─ model: mlx_lm.server on a node (Tailscale)
```

## Run (locally / over Tailscale)

```sh
# 1. Serve the mesh as MCP over HTTP (on the host with the mesh manifest):
chp-host mcp --http --bind 127.0.0.1 --port 8810 --environment ~/.chp/mesh.json

# 2. Configure + start the cockpit:
cp .env.example .env.local       # fill CHP_GATEWAY_KEY, point CHP_MODEL_BASE_URL at a node
npm install
npm run dev                      # http://localhost:3000
```

## Governance

The OpenHarness `approve` callback assesses every tool call: `allow` runs,
`require_approval` is denied unless `CHP_AUTO_APPROVE=1`, `block` is denied
(fail-closed for mutating tools). So an operator can drive the mesh while
high-risk actions stay gated — and the whole run is evidenced under one
correlation id (replay via `chp-host mesh audit`).

## Config

See `.env.example`. Key knobs: `CHP_MCP_SSE_URL`, `CHP_GATEWAY_KEY`,
`CHP_SAFETY_URL`, `CHP_MODEL_BASE_URL` / `CHP_MODEL_ID`, `CHP_TOOLS`.
