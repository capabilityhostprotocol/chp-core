/**
 * CHP Cockpit — agent route over the governed mesh.
 *
 * Connects to the CHP mesh over HTTP/SSE MCP (`chp-host mcp --http`), so the
 * agent's tools are governed mesh capabilities. Every tool call is assessed via
 * chp.adapters.safety.assess; high-risk actions are gated. The model runs on a
 * node (not this host). Internal/authenticated use only.
 */
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { tool, type ToolSet } from "ai";
import { z } from "zod";
import {
  Agent, Conversation, toRunner, apply,
  withTurnTracking, withCompaction, withRetry, withPersistence,
  extractUserInput, connectMCPServers,
  type SessionStore, type ToolCallInfo,
} from "@openharness/core";

// ── Config ───────────────────────────────────────────────────────────
const MCP_SSE_URL = process.env.CHP_MCP_SSE_URL ?? "http://127.0.0.1:8810/sse";
const KEY = process.env.CHP_GATEWAY_KEY ?? process.env.CHP_HOST_API_KEY ?? "";
const SAFETY_URL = process.env.CHP_SAFETY_URL ?? "http://127.0.0.1:8803";
const MODEL_BASE_URL = process.env.CHP_MODEL_BASE_URL ?? "http://127.0.0.1:8081/v1";
const MODEL_ID = process.env.CHP_MODEL_ID ?? "mlx-community/Qwen3-4B-Instruct-2507-4bit";
const TOOL_FILTER = (process.env.CHP_TOOLS ?? "filesystem,conformance,host_stats,host_version,scout,git")
  .split(",").map((s) => s.trim()).filter(Boolean);
const AUTO_APPROVE = process.env.CHP_AUTO_APPROVE === "1";

const model = createOpenAICompatible({ name: "mlx", baseURL: MODEL_BASE_URL }).chatModel(MODEL_ID);

// ── Governance: assess every tool call via chp.adapters.safety.assess ──
const capMap = new Map<string, string>(); // MCP tool name → CHP capability id
async function buildCapMap(): Promise<void> {
  if (capMap.size) return;
  try {
    const r = await fetch(`${SAFETY_URL}/capabilities`, { headers: { "X-CHP-Key": KEY } });
    const d = await r.json();
    for (const c of d.capabilities ?? []) capMap.set(String(c.id).replaceAll(".", "_"), c.id);
  } catch { /* assess() falls back to the raw tool name (pattern match still works) */ }
}
async function assess(capId: string, input: unknown): Promise<{ level: string; recommendation: string }> {
  try {
    const r = await fetch(`${SAFETY_URL}/invoke`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-CHP-Key": KEY },
      body: JSON.stringify({ capability_id: "chp.adapters.safety.assess", payload: { capability_id: capId, payload: input } }),
    }).then((x) => x.json());
    if (r?.outcome !== "success") throw new Error("assess failed");
    return { level: r.data?.level ?? "unknown", recommendation: r.data?.recommendation ?? "allow" };
  } catch {
    const risky = /write|delete|update|restart|stop|install|push|exec|bash|run|create/i.test(capId);
    return { level: "unknown", recommendation: risky ? "block" : "allow" }; // fail-closed for mutating tools
  }
}
async function approve(toolCall: ToolCallInfo): Promise<boolean> {
  const capId = capMap.get(toolCall.toolName) ?? toolCall.toolName;
  const { recommendation } = await assess(capId, toolCall.input);
  if (recommendation === "block") return false;
  if (recommendation === "require_approval" && !AUTO_APPROVE) return false;
  return true;
}

// ── Narration tool (shown prominently in the UI) ───────────────────────
const announce = tool({
  description: "Narrate what you are about to do (one short sentence). Shown prominently to the operator.",
  inputSchema: z.object({ message: z.string() }),
  execute: async ({ message }) => message,
});

// ── Lazy mesh connection + agent (built once) ──────────────────────────
let agentPromise: Promise<Agent> | null = null;
function getAgent(): Promise<Agent> {
  if (!agentPromise) {
    agentPromise = (async () => {
      await buildCapMap();
      const { tools: all } = await connectMCPServers({
        chp: { type: "sse", url: MCP_SSE_URL, headers: { "X-CHP-Key": KEY } },
      });
      const tools: ToolSet = Object.fromEntries(
        Object.entries(all).filter(([n]) => TOOL_FILTER.some((f) => n.includes(f))),
      );
      tools.announce = announce;
      return new Agent({
        name: "chp-cockpit",
        systemPrompt:
          "You operate the Capability Host Protocol (CHP) mesh. Your tools are governed mesh " +
          "capabilities across a fleet of nodes. Use them to accomplish the operator's task; " +
          "high-risk actions may be denied by safety policy — report denials plainly. " +
          "Use `announce` to narrate each step in one sentence. Cite files/paths you read.",
        model, tools, maxSteps: 24, approve,
      });
    })();
  }
  return agentPromise;
}

// ── Session store + conversation cache ─────────────────────────────────
const messageStore = new Map<string, any[]>();
const store: SessionStore = {
  async load(id) { return messageStore.get(id); },
  async save(id, m) { messageStore.set(id, m); },
};
const conversations = new Map<string, Conversation>();
async function getConversation(id: string): Promise<Conversation> {
  let conv = conversations.get(id);
  if (!conv) {
    const agent = await getAgent();
    const runner = apply(
      toRunner(agent),
      withTurnTracking(),
      withCompaction({ contextWindow: 32_000, model: agent.model }),
      withRetry(),
      withPersistence({ store, sessionId: id }),
    );
    conv = new Conversation({ runner, sessionId: id, store });
    conversations.set(id, conv);
  }
  return conv;
}

export async function POST(req: Request) {
  const { id, messages } = await req.json();
  const conv = await getConversation(id ?? crypto.randomUUID());
  const input = await extractUserInput(messages);
  return conv.toResponse(input, { signal: req.signal });
}
