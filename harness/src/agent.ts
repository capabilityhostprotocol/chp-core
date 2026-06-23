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
import { randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import chalk from "chalk";
import {
  Agent,
  Conversation,
  toRunner,
  apply,
  withTurnTracking,
  withRetry,
  withPersistence,
  connectMCPServers,
  closeMCPClients,
  type ToolCallInfo,
  type SessionStore,
} from "@openharness/core";

// ── Config ──────────────────────────────────────────────────────────────
const MESH = process.env.CHP_MESH ?? `${homedir()}/.chp/mesh.json`;
// Default to the gateway's OpenAI shim → inference runs as a capacity-routed,
// evidenced mesh capability (chp.adapters.mlx.chat). Override to hit a node directly.
const MODEL_BASE_URL = process.env.CHP_MODEL_BASE_URL ?? "http://127.0.0.1:8800/v1";
const MODEL_ID = process.env.CHP_MODEL_ID ?? "mlx-community/Qwen3-4B-Instruct-2507-4bit";
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

// A1 — small models misread structured tool output (scout returned `files`, the 4B
// still said "not found"). Flatten the common shapes into explicit text before the
// model sees them, and wrap each tool's execute to apply it.
function summarizeToolResult(raw: any): any {
  let data: any = raw;
  if (typeof raw === "string") { try { data = JSON.parse(raw); } catch { return raw; } }
  // MCP results often wrap the payload in a content array of {type:'text', text}.
  if (data && Array.isArray(data.content)) {
    const t = data.content.find((c: any) => c?.type === "text")?.text;
    if (t) { try { data = JSON.parse(t); } catch { return t; } }
  }
  const obj = data && typeof data === "object" ? data : {};
  const files = obj.files ?? obj.citations;
  if (Array.isArray(files) && files.length) {
    const lines = files.map((f: any) =>
      typeof f === "string" ? f : `${f.path}${f.line_range ? ":" + f.line_range : ""}`);
    return `Found ${files.length} file(s):\n${lines.map((l: string) => "- " + l).join("\n")}\n` +
      "(Report these path(s)/line-range(s) as the answer — do NOT say 'not found'.)";
  }
  if (Array.isArray(obj.violations)) {
    return obj.violations.length
      ? `Conformance: ${obj.violations.length} violation(s):\n` +
        obj.violations.map((v: any) => "- " + JSON.stringify(v)).join("\n")
      : "Conformance: clean (no violations).";
  }
  return raw;
}

function wrapToolResults(tools: Record<string, any>): Record<string, any> {
  return Object.fromEntries(Object.entries(tools).map(([n, t]) => {
    const orig = t?.execute;
    if (typeof orig !== "function") return [n, t];
    return [n, { ...t, execute: async (args: any, opts: any) => summarizeToolResult(await orig(args, opts)) }];
  }));
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
  const curated = filter.length
    ? Object.fromEntries(Object.entries(allTools).filter(([n]) => filter.some((f) => n.includes(f))))
    : allTools;
  const tools = wrapToolResults(curated); // A1: format structured results for small models
  console.log(chalk.dim(`mesh tools: ${Object.keys(allTools).length} available → ${Object.keys(tools).length} enabled`));

  // P1 governance: build the tool→capability map so every tool call can be assessed.
  await buildCapMap();
  console.log(chalk.dim(`governance: every tool call assessed via chp.adapters.safety.assess`));

  // X-CHP-Key authenticates the gateway shim; harmless when pointing at a node directly.
  const model = createOpenAICompatible({
    name: "mlx", baseURL: MODEL_BASE_URL, headers: { "X-CHP-Key": GATEWAY_KEY },
  }).chatModel(MODEL_ID);

  // P3 — a read-only `explore` subagent (mesh read tools). The main agent delegates
  // exploration to it via the auto-injected `task` tool; it keeps repo-spelunking
  // out of the main context (OpenHarness runs subagents with their own window).
  const readOnly = Object.fromEntries(
    Object.entries(tools).filter(([n]) => /read_file|list_directory|glob|grep|scout|stat_path/.test(n)),
  );
  const explore = new Agent({
    name: "explore",
    description: "Read-only mesh exploration — search and read repo files across the fleet.",
    systemPrompt:
      "You explore the CHP repo over the mesh (read-only). Call scout_query (or grep) to locate code. " +
      "Scout returns a `files` list of {path, line_range} — report each one VERBATIM as your finding. " +
      "NEVER answer 'not found' if scout returned any files; pass the paths/line ranges through.",
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

  // C1 — opt-in transcript capture (CHP_CAPTURE_TRACES) feeds the flywheel corpus.
  const sessionId = randomUUID();
  const messageStore = new Map<string, any[]>();
  const store: SessionStore = {
    async load(id) { return messageStore.get(id); },
    async save(id, m) { messageStore.set(id, m); },
  };
  const runner = apply(toRunner(agent), withTurnTracking(), withRetry(),
                       withPersistence({ store, sessionId }));
  const chat = new Conversation({ runner, sessionId, store });

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

  // C1 — append the full transcript to the flywheel corpus (opt-in).
  const capturePath = process.env.CHP_CAPTURE_TRACES;
  if (capturePath) {
    const msgs = (await store.load(sessionId)) ?? [];
    mkdirSync(dirname(capturePath), { recursive: true });
    appendFileSync(capturePath, JSON.stringify({ messages: msgs, meta: { task, ts: Date.now() } }) + "\n");
    console.log(chalk.dim(`\ncaptured transcript (${msgs.length} messages) → ${capturePath}`));
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
