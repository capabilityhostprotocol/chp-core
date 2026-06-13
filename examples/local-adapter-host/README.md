# local-adapter-host

A standalone CHP host that registers the five `chp-adapter-*` packages and serves
them over HTTP, for driving each adapter against real/local services. Depends only
on `chp-core` + the adapter packages — **not** on chp-agent.

See `../../docs/local-testing.md` for the full per-adapter walkthrough.

## Quick start

```bash
# 1. Install everything editable (from the chp-dev repo root)
scripts/dev-install.sh

# 2. Configure credentials
cp .env.example .env        # then edit; `set -a; . ./.env; set +a` to load

# 3. (optional) local Postgres
docker compose up -d postgres

# 4. Serve — run from THIS directory so mcp.json / webhook.secrets.json resolve
cd examples/local-adapter-host
python server.py --port 8765
```

The host prints which adapters registered (and why any were skipped).

## Invoke

```bash
curl -s localhost:8765/capabilities | python -m json.tool

curl -s -X POST localhost:8765/invoke -H 'content-type: application/json' -d '{
  "capability_id": "chp.adapters.github.get_repo",
  "payload": {"owner": "capabilityhostprotocol", "repo": "chp-core"}
}' | python -m json.tool
```

The response includes a `correlation` id; replay its evidence chain:

```bash
curl -s localhost:8765/replay/<correlation_id> | python -m json.tool
```

## Inbound (webhook / slack)

Use `sign.py` to produce a correctly signed request, then feed it to the inbound
capability:

```bash
echo '{"action":"opened"}' > /tmp/body.json
python sign.py github --secret dev-webhook-secret --body-file /tmp/body.json
# prints the signed headers + a ready-to-run curl to POST /invoke
```

## Files

| File | Purpose |
|---|---|
| `host_definition.py` | builds the host; registers all five adapters fail-soft |
| `server.py` | serves the host over HTTP |
| `sign.py` | generate signed webhook/slack payloads for inbound testing |
| `mcp_demo_server.py` | a bundled FastMCP server so MCP works offline |
| `mcp.json` | MCP server config (points at the demo server) |
| `webhook.secrets.json` | per-provider webhook signing secrets |
