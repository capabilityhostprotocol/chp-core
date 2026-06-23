/**
 * P0 bridge check (no model needed): connect to the CHP mesh over MCP and list
 * the capabilities that come through as tools. Validates that
 * `chp-host mcp --environment <mesh>` → OpenHarness toolset works end to end.
 *
 *   npm run list-tools
 */
import { homedir } from "node:os";
import { connectMCPServers, closeMCPClients } from "@openharness/core";

const MESH = process.env.CHP_MESH ?? `${homedir()}/.chp/mesh.json`;
const KEYCHAIN_KEYS = ["CHP_HOST_API_KEY", "CHP_PEER_0_KEY", "CHP_PEER_1_KEY", "CHP_NAS_KEY", "CHP_NAS_IP"];

async function main() {
  console.log(`connecting to mesh via: chp-host mcp --environment ${MESH}`);
  const t0 = Date.now();
  const { clients, tools } = await connectMCPServers({
    chp: {
      type: "stdio",
      command: "chp-host",
      args: ["mcp", "--environment", MESH, "--secrets-from-keychain", ...KEYCHAIN_KEYS],
    },
  });
  const names = Object.keys(tools).sort();
  console.log(`\n✓ ${names.length} mesh capabilities as MCP tools (${Date.now() - t0}ms):\n`);
  for (const n of names) console.log("  " + n);
  await closeMCPClients(clients);
}

main().catch((e) => { console.error(e); process.exit(1); });
