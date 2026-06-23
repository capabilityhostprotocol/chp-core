# chp-harness — OpenHarness agents over the CHP mesh

An [OpenHarness](https://open-harness.dev) agent whose **tools are the CHP mesh**.
It connects to `chp-host mcp --environment <mesh>` over MCP (stdio), so every
governed capability across the fleet becomes a tool, and it reasons with a local
MLX model. This is the TS agent-harness layer (the Python `examples/chp-develops-chp/`
remains the no-framework reference).

## Run

```sh
export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
# point at a model server (keep models OFF the control-plane host):
export CHP_MODEL_BASE_URL=http://<inference-tailscale-ip>:8081/v1
export CHP_MODEL_ID=mlx-community/Qwen3-4B-Instruct-2507-4bit

npm install
npm run list-tools                       # P0 bridge check: mesh caps as MCP tools
npm run agent -- "read X and summarize"  # run an agent task over the mesh
```

## What it does

- **P0 — MCP bridge.** `connectMCPServers` spawns `chp-host mcp --environment
  ~/.chp/mesh.json` and exposes the whole mesh (~150 caps) as OpenHarness tools.
  Curated to a task-relevant subset via `CHP_TOOLS` (small models can't reason over
  150 schemas).
- **P1 — governance bridge.** The OpenHarness `approve` callback assesses every tool
  call via `chp.adapters.safety.assess` (on the primary host): `allow` runs,
  `require_approval` is denied unless `CHP_AUTO_APPROVE=1`, `block` is denied.
  Assessment is fail-closed for mutating tools. Verified: a low-risk read passes
  (`safety:low → allow`); `host.restart` is gated (`safety:high → require_approval` →
  `ToolDeniedError`).

## Config

| Env | Default | Meaning |
|-----|---------|---------|
| `CHP_MODEL_BASE_URL` | `http://localhost:8081/v1` | OpenAI-compatible model server (run it on a node with RAM, not the control-plane host) |
| `CHP_MODEL_ID` | `mlx-community/Qwen3-14B-4bit` | served model id |
| `CHP_MESH` | `~/.chp/mesh.json` | mesh manifest fronted by `chp-host mcp` |
| `CHP_TOOLS` | `filesystem,conformance,host_stats,host_version,scout` | substring filter on tool names |
| `CHP_SAFETY_URL` | `http://127.0.0.1:8803` | host exposing `safety.assess` |
| `CHP_AUTO_APPROVE` | unset | allow `require_approval` verdicts |

## Operational notes

- **Models off the primary.** The 24 GB control-plane host OOM'd twice loading large
  models; run the model on the inference node and bind it to Tailscale
  (`mlx.start_server host=0.0.0.0`), pointing `CHP_MODEL_BASE_URL` at it.
- If a model download stalls at ~15 MB, disable hf-xet: `HF_HUB_DISABLE_XET=1`.
