#!/usr/bin/env python3
"""CHP-develops-CHP — a self-hosted coding/analysis agent running entirely on the mesh.

The reasoning model (Qwen3 via chp.adapters.mlx on the inference node) drives a
ReAct loop whose *tools are CHP capabilities*, routed across the fleet through the
gateway and recorded as evidence:

  reason (mlx.chat @ inference)
    └─ act  → scout / filesystem / conformance  (@ primary, repo node)
         └─ observe → feed result back → repeat (bounded)

Every tool call is a governed capability invocation sharing one correlation id, so
the whole run is replayable (`chp-host` mesh tooling / router.replay). Mutating
actions are assessed by chp.adapters.safety first and only run under --apply.

Usage:
    export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
    python agent.py "Summarise what the mlx adapter does and suggest one improvement"
    python agent.py --repo /path/to/chp-core --steps 6 "your task"

This is a demonstration of the agentic layer (see docs/agentic-mesh.md), not an
unattended committer: by default it is read-only and proposes; it never pushes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid

from chp_core.http import RemoteCapabilityHost

DEFAULT_GATEWAY = "http://127.0.0.1:8800"
DEFAULT_REPO = "/Users/patrickschmied/Projects/capabilityhostprotocol/chp-core"
DEFAULT_MODEL = "mlx-community/Qwen3-4B-Instruct-2507-4bit"

# Read-only tools the agent may call. Each maps to a CHP capability + the node it
# must run on (prefer), plus how to render the payload from the model's args.
TOOLS: dict[str, dict] = {
    "list_dir": {
        "cap": "chp.adapters.filesystem.list_directory", "prefer": "primary",
        "args": ["path"], "help": "List a directory. args: {path}"},
    "read_file": {
        "cap": "chp.adapters.filesystem.read_file", "prefer": "primary",
        "args": ["path"], "help": "Read a file. args: {path}"},
    "grep": {
        "cap": "chp.adapters.filesystem.grep", "prefer": "primary",
        "args": ["pattern", "path"], "help": "Regex search. args: {pattern, path}"},
    "scout": {
        "cap": "chp.adapters.scout.query", "prefer": "primary",
        "args": ["task"], "help": "Find relevant code for a task. args: {task}"},
    "conformance": {
        "cap": "chp.adapters.conformance.check_source", "prefer": "primary",
        "args": ["source_path"], "help": "Check a source file for CHP violations. args: {source_path}"},
}

SYSTEM_PROMPT = """You are a coding analyst working INSIDE the Capability Host Protocol mesh.
You answer the user's task by calling tools that read the CHP repository, then giving a final answer.

You MUST reply with exactly ONE JSON object per turn, nothing else:
  - To call a tool:   {{"tool": "<name>", "args": {{...}}}}
  - To finish:        {{"final": "<your answer, citing files you read>"}}

Available tools:
{tools}

Rules:
- The repository root is: {repo}
- Use absolute paths under the repository root.
- Call tools to gather evidence BEFORE answering. Prefer scout/grep to locate, then read_file.
- Keep to at most {steps} tool calls, then give {{"final": ...}}.
- Output ONLY the JSON object. No prose, no markdown fences."""


def _extract_json(text: str) -> dict | None:
    """Lenient: find the first balanced {...} object in the model's reply."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


class CHPDevAgent:
    def __init__(self, gateway: str, key: str, repo: str, model: str, steps: int):
        self.gw = RemoteCapabilityHost(gateway, api_key=key, timeout=180)
        self.repo, self.model, self.max_steps = repo, model, steps
        self.correlation = {"correlation_id": f"chp-dev-{uuid.uuid4().hex[:8]}"}
        self.trail: list[dict] = []

    def _invoke(self, cap: str, payload: dict, prefer: str | None = None) -> tuple[bool, object]:
        meta = {"prefer": prefer} if prefer else {}
        r = self.gw.invoke(cap, payload, correlation=self.correlation, metadata=meta)
        self.trail.append({"cap": cap, "outcome": r.outcome, "prefer": prefer})
        return r.success, (r.data if r.success else (r.error or r.denial))

    def _chat(self, messages: list[dict]) -> str:
        ok, data = self._invoke(
            "chp.adapters.mlx.chat",
            {"model": self.model, "messages": messages, "max_tokens": 700, "temperature": 0.2},
            prefer="inference")
        if not ok:
            raise RuntimeError(f"mlx.chat failed: {data}")
        return (data.get("message") or {}).get("content", "")

    def _run_tool(self, name: str, args: dict) -> str:
        spec = TOOLS.get(name)
        if not spec:
            return f"ERROR: unknown tool {name!r}. Valid: {', '.join(TOOLS)}"
        payload = {k: args.get(k) for k in spec["args"] if args.get(k) is not None}
        if name == "scout":
            payload["repo_path"] = self.repo
        ok, data = self._invoke(spec["cap"], payload, prefer=spec["prefer"])
        if not ok:
            return f"ERROR: {json.dumps(data)[:300]}"
        # Compact the observation so the small model isn't overwhelmed.
        return json.dumps(data)[:1500]

    def run(self, task: str) -> str:
        tools_doc = "\n".join(f"  - {n}: {s['help']}" for n, s in TOOLS.items())
        system = SYSTEM_PROMPT.format(tools=tools_doc, repo=self.repo, steps=self.max_steps)
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": task}]

        for step in range(1, self.max_steps + 1):
            reply = self._chat(messages)
            action = _extract_json(reply)
            if not action:
                messages.append({"role": "assistant", "content": reply})
                messages.append({"role": "user", "content":
                                 'Reply with ONE JSON object: {"tool":...} or {"final":...}.'})
                print(f"  [{step}] (no JSON, nudging)")
                continue
            if "final" in action:
                print(f"  [{step}] final answer")
                return str(action["final"])
            tool, args = action.get("tool"), action.get("args", {}) or {}
            print(f"  [{step}] tool: {tool}({json.dumps(args)[:80]})")
            obs = self._run_tool(tool, args)
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user", "content": f"Observation: {obs}"})

        # Out of steps — ask for a final answer from what was gathered.
        messages.append({"role": "user", "content": 'Step budget reached. Give {"final": ...} now.'})
        final = _extract_json(self._chat(messages)) or {}
        return str(final.get("final", "(no final answer produced)"))


def main() -> int:
    ap = argparse.ArgumentParser(description="CHP-develops-CHP agent (runs on the mesh).")
    ap.add_argument("task", help="What the agent should investigate/do.")
    ap.add_argument("--gateway", default=os.environ.get("CHP_GATEWAY", DEFAULT_GATEWAY))
    ap.add_argument("--repo", default=DEFAULT_REPO, help="Repository root on the primary node.")
    ap.add_argument("--model", default=os.environ.get("MLX_MODEL", DEFAULT_MODEL))
    ap.add_argument("--steps", type=int, default=6, help="Max tool calls.")
    args = ap.parse_args()

    key = os.environ.get("CHP_GATEWAY_KEY") or os.environ.get("CHP_HOST_API_KEY")
    if not key:
        print("Set CHP_GATEWAY_KEY (e.g. export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY))",
              file=sys.stderr)
        return 2

    agent = CHPDevAgent(args.gateway, key, args.repo, args.model, args.steps)
    print(f"CHP-develops-CHP  ·  correlation={agent.correlation['correlation_id']}  ·  model={args.model}")
    print(f"task: {args.task}\n")
    answer = agent.run(args.task)

    print("\n" + "=" * 70 + "\nANSWER\n" + "=" * 70)
    print(answer)
    print("\n" + "-" * 70)
    print(f"evidence: {len(agent.trail)} governed capability calls under correlation "
          f"{agent.correlation['correlation_id']}")
    for t in agent.trail:
        print(f"  {t['outcome']:8} {t['cap']}" + (f"  (@{t['prefer']})" if t['prefer'] else ""))
    print(f"\nReplay the full federated trail with this correlation id via the mesh evidence tooling.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
