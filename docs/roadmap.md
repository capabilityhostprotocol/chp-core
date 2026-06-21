# CHP Roadmap

> CHP makes capability execution visible, replayable, and ready for governance.

## Shipped

**v0.1 — Local Execution Evidence**  
Protocol spec, JSON schemas, Python reference host (`chp-core`), TypeScript types
(`@capabilityhostprotocol/types`), append-only SQLite evidence store, replay by
correlation ID, conformance suite.

**v0.1 Adapter Tier — 66 Governed Adapters**  
Full `chp-adapter-*` library: HTTP, filesystem, git, GitHub, Radicle, audit, secrets,
CI, conformance, safety, planning, delegation, composition, jobs, HuggingFace, TEI,
vLLM, Scout, SGLang, smolagents, Tailscale, and more. Every adapter wraps its
operations in evidence. See `docs/capabilities/adapter-build-status.md`.

**v0.1 Host Infrastructure — `chp-host`**  
`chp-host serve/mcp/gateway/init/mesh` CLI. Profile-based host config, multi-host
router, Tailscale mesh, `chp-host init` one-command node setup, `chp-host mesh`
peer management, zero-arg gateway via `~/.chp/mesh.json`.

**Claude Desktop / MCP Integration**  
`chp-host mcp` exposes all capabilities as MCP tools. Every Claude tool call is
governed and evidenced. See `docs/claude-desktop-mcp.md`.

## Active — Multi-Host Mesh

Ongoing work to make distributed CHP clusters feel natural:

- **Bootstrap scripts** — `scripts/bootstrap-mac.sh`, `scripts/bootstrap-linux.sh`
- **Service persistence** — LaunchAgent on macOS, systemd on Linux, auto-loaded by init
- **Tailscale mesh** — peer discovery via `chp.adapters.tailscale.chp_hosts`
- **Edge nodes** — Synology NAS (port 8802), Raspberry Pi (port 8801)

## Next — v0.2 Protocol

The v0.2 protocol layer adds tamper-evident evidence and richer query:

- **Evidence integrity** — JCS hash chains, ed25519 signed bundles, graduated assurance
  (`none` / `hash-chain` / `signed`). Design: `docs/design/evidence-integrity-v0.2.md`
- **Streaming evidence** — chunked evidence events during long-running capabilities
- **Evidence query API** — filter by capability_id, time range, outcome, issue_id
- **Capability versioning** — schema evolution path, `deprecated` lifecycle state
- **`chp verify`** — portable bundle verification CLI

## Guiding Rule

Local visibility should be free. Production trust should be paid.
