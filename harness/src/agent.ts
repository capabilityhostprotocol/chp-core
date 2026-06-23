/**
 * CHP × OpenHarness — Phase 0 spike.
 *
 * An OpenHarness Agent whose tools ARE the CHP mesh: it connects (MCP, stdio) to
 * `chp-host mcp --environment <mesh>`, so every governed capability across the
 * fleet (filesystem, scout, conformance, git, host, mlx, …) becomes a tool. The
 * model is a local MLX server (OpenAI-compatible) on the primary.
 *
 * Each MCP tool call carries the chp-host MCP-session correlation id, so the run
 * is replayable via the CHP evidence tooling (`chp-host mesh audit` / replay).
 *
 *   # terminal A is implicit — the stdio transport spawns chp-host mcp for us
 *   export CHP_MODEL_BASE_URL=http://localhost:8081/v1   # primary Qwen3-14B
 *   export CHP_MODEL_ID=mlx-community/Qwen3-14B-4bit
 *   npm run agent -- "What capabilities does the mlx adapter expose? Cite the file."
 */

import { homedir } from "node:os";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import chalk from "chalk";
import {
  Agent,
  Conversation,
  toRunner,
  apply,
  withTurnTracking,
  withRetry,
  connectMCPServers,
  closeMCPClients,
  type ToolCallInfo,
} from "@openharness/core";

// ── Config ──────────────────────────────────────────────────────────────
const MESH = process.env.CHP_MESH ?? `${homedir()}/.chp/mesh.json`;
const MODEL_BASE_URL = process.env.CHP_MODEL_BASE_URL ?? "http://localhost:8081/v1";
const MODEL_ID = process.env.CHP_MODEL_ID ?? "mlx-community/Qwen3-14B-4bit";
const GATEWAY = process.env.CHP_GATEWAY ?? "http://127.0.0.1:8800";
const GATEWAY_KEY = process.env.CHP_GATEWAY_KEY ?? process.env.CHP_HOST_API_KEY ?? "";
// The safety adapter lives on the primary host (the gateway doesn't surface it).
const SAFETY_URL = process.env.CHP_SAFETY_URL ?? "http://127.0.0.1:8803";
// require_approval verdicts: deny by default (safe); set CHP_AUTO_APPROVE=1 to allow.
const AUTO_APPROVE = process.env.CHP_AUTO_APPROVE === "1";

// ── Governance: assess a capability via chp.adapters.safety.assess ───────
async function hostInvoke(base: string, capabilityId: string, payload: unknown): Promise<any> {
  const res = await fetch(`${base}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CHP-Key": GATEWAY_KEY },
    body: JSON.stringify({ capability_id: capabilityId, payload }),
  });
  return res.json();
}

async function assess(capId: string, input: unknown): Promise<{ level: string; recommendation: string }> {
  try {
    const r = await hostInvoke(SAFETY_URL, "chp.adapters.safety.assess", { capability_id: capId, payload: input });
    const d = r?.data ?? {};
    if (r?.outcome !== "success") throw new Error(JSON.stringify(r?.error ?? r));
    return { level: d.level ?? "unknown", recommendation: d.recommendation ?? "allow" };
  } catch (e) {
    // Fail CLOSED for clearly mutating tools, open otherwise — never silently allow a write we couldn't assess.
    const risky = /write|delete|update|restart|stop|install|push|exec|bash|run|create/i.test(capId);
    console.warn(`    ⚠ safety.assess unavailable (${String(e).slice(0, 80)}) — ${risky ? "denying (fail-closed)" : "allowing low-risk"}`);
    return { level: "unknown", recommendation: risky ? "block" : "allow" };
  }
}
// Node keys the mesh router needs to authenticate to remote hosts (names only).
const KEYCHAIN_KEYS = [
  "CHP_HOST_API_KEY",
  "CHP_PEER_0_KEY",
  "CHP_PEER_1_KEY",
  "CHP_NAS_KEY",
  "CHP_NAS_IP",
];

const SYSTEM_PROMPT =
  "You are an agent operating over the Capability Host Protocol (CHP) mesh. " +
  "Your tools are governed CHP capabilities spanning a fleet of nodes (filesystem, " +
  "code search/scout, conformance, git, host stats, and local LLM inference). " +
  "Use them to gather evidence and answer the user's task; cite the files/paths you read. " +
  "Prefer read-only tools first. Be concise.";

// MCP tool name → CHP capability id (mcp_server uses cap_id.replace(".", "_")).
const capMap = new Map<string, string>();
async function buildCapMap(): Promise<void> {
  const res = await fetch(`${GATEWAY}/capabilities`, { headers: { "X-CHP-Key": GATEWAY_KEY } });
  const data = await res.json();
  for (const c of data.capabilities ?? []) capMap.set(String(c.id).replaceAll(".", "_"), c.id);
}

// P1 governance bridge: assess every tool call via chp.adapters.safety.assess.
async function approve(toolCall: ToolCallInfo): Promise<boolean> {
  const capId = capMap.get(toolCall.toolName) ?? toolCall.toolName;
  const { level, recommendation } = await assess(capId, toolCall.input);
  const tag = recommendation === "block" ? chalk.red("BLOCK")
    : recommendation === "require_approval" ? chalk.yellow("APPROVE?")
    : chalk.green("allow");
  console.log(`  ${chalk.yellow("○")} ${chalk.cyan(toolCall.toolName)} ` +
    `${chalk.dim(`[safety:${level} → ${recommendation}]`)} ${tag}`);
  if (recommendation === "block") { console.log(`    ${chalk.red("✗ denied by safety.assess")}`); return false; }
  if (recommendation === "require_approval" && !AUTO_APPROVE) {
    console.log(`    ${chalk.red("✗ requires approval (set CHP_AUTO_APPROVE=1 to allow)")}`); return false;
  }
  return true;
}

async function main() {
  const task = process.argv.slice(2).join(" ").trim();
  if (!task) {
    console.error('Usage: npm run agent -- "your task"');
    process.exit(2);
  }

  console.log(chalk.bold.cyan("chp-harness") + chalk.dim(`  · model ${MODEL_ID} · mesh ${MESH}`));
  console.log(chalk.dim("connecting to the mesh over MCP (chp-host mcp)..."));

  const { clients, tools: allTools } = await connectMCPServers({
    chp: {
      type: "stdio",
      command: "chp-host",
      args: ["mcp", "--environment", MESH, "--secrets-from-keychain", ...KEYCHAIN_KEYS],
    },
  });
  // The mesh exposes ~150 capabilities; a small local model can't reason over that
  // many tool schemas. Curate to a task-relevant subset (override via CHP_TOOLS,
  // comma-separated substrings; empty = all).
  const filter = (process.env.CHP_TOOLS ?? "filesystem,conformance,host_stats,host_version,scout")
    .split(",").map((s) => s.trim()).filter(Boolean);
  const tools = filter.length
    ? Object.fromEntries(Object.entries(allTools).filter(([n]) => filter.some((f) => n.includes(f))))
    : allTools;
  console.log(chalk.dim(`mesh tools: ${Object.keys(allTools).length} available → ${Object.keys(tools).length} enabled`));

  // P1 governance: build the tool→capability map so every tool call can be assessed.
  await buildCapMap();
  console.log(chalk.dim(`governance: every tool call assessed via chp.adapters.safety.assess`));

  const model = createOpenAICompatible({ name: "mlx", baseURL: MODEL_BASE_URL }).chatModel(MODEL_ID);

  // P3 — a read-only `explore` subagent (mesh read tools). The main agent delegates
  // exploration to it via the auto-injected `task` tool; it keeps repo-spelunking
  // out of the main context (OpenHarness runs subagents with their own window).
  const readOnly = Object.fromEntries(
    Object.entries(tools).filter(([n]) => /read_file|list_directory|glob|grep|scout|stat_path/.test(n)),
  );
  const explore = new Agent({
    name: "explore",
    description: "Read-only mesh exploration — search and read repo files across the fleet.",
    systemPrompt: "You explore the CHP repo over the mesh (read-only). Return concise file:line findings.",
    model,
    tools: readOnly,
    maxSteps: 12,
  });
  console.log(chalk.dim(`subagent: explore (${Object.keys(readOnly).length} read-only tools)`));

  const agent = new Agent({
    name: "chp-agent",
    systemPrompt: SYSTEM_PROMPT +
      " For read-only exploration (finding/reading code), delegate to the `explore` subagent via the task tool.",
    model,
    tools,
    maxSteps: 12,
    approve,
    subagents: [explore],
    onSubagentEvent: (path: string[], ev: any) => {
      if (ev.type === "tool.done") console.log(chalk.magenta(`    ⌁ ${path.join(">")}: ${ev.toolName}`));
      if (ev.type === "done") console.log(chalk.magenta(`    ⌁ ${path.join(">")} done`));
    },
  });

  const runner = apply(toRunner(agent), withTurnTracking(), withRetry());
  const chat = new Conversation({ runner });

  console.log(chalk.dim(`task: ${task}\n`));
  let streaming = false;
  for await (const event of chat.send(task)) {
    switch (event.type) {
      case "text.delta":
        if (!streaming) { process.stdout.write("  "); streaming = true; }
        process.stdout.write(event.text);
        break;
      case "text.done":
        if (streaming) { process.stdout.write("\n"); streaming = false; }
        break;
      case "tool.done":
        console.log(`  ${chalk.green("✔")} ${chalk.dim(event.toolName)}`);
        break;
      case "tool.error":
        console.log(`  ${chalk.red("✗")} ${chalk.dim(event.toolName)} ${chalk.red(String(event.error))}`);
        break;
      case "error":
        console.error(`  ${chalk.red("✗")} ${event.error.message}`);
        break;
      case "turn.done":
        if (event.usage.totalTokens) console.log(chalk.dim(`  · ${event.usage.totalTokens} tokens`));
        break;
    }
  }

  await agent.close();
  await closeMCPClients(clients);
  console.log(chalk.dim("\nEvidence: each tool call carried the chp-host MCP session correlation — " +
    "replay it via `chp-host mesh audit`."));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
