#!/usr/bin/env python3
"""A coding agent that runs on the mesh and collaborates with scout.

Pipeline for one focused, single-file change:
  1. scout (FastContext, tool-calling) locates the relevant file for the task.
  2. read_file pulls the current source (over the mesh).
  3. the coder model (MLX, default Qwen3-14B on the primary) rewrites the file.
  4. safety.assess gates the write (abort if it recommends "block").
  5. (--apply) write_file applies it, then conformance.check_source verifies.

Read-only/propose by default; --apply writes (to the working tree on the repo
node — run it on a branch). Never commits or pushes. Every step is a governed,
correlation-tagged capability call (see the printed evidence trail).

    export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
    python coder.py "Add a module docstring to chp_adapter_mlx/__init__.py if missing"
    python coder.py --apply --file packages/chp-adapter-mlx/chp_adapter_mlx/__init__.py "..."
"""

from __future__ import annotations

import argparse
import os

from mesh_lib import MeshClient, strip_code_fence

DEFAULT_REPO = "/Users/patrickschmied/Projects/capabilityhostprotocol/chp-dev"
PRIMARY_MODEL = "mlx-community/Qwen3-14B-4bit"

CODER_SYS = """You are a careful coding agent contributing to the Capability Host Protocol.
You are given a task, a target file path, and its CURRENT contents.
Return the COMPLETE new contents of that one file implementing the task — nothing else.
Rules:
- Output ONLY the file contents (you may wrap them in a single ``` fenced block).
- Make the smallest change that satisfies the task; preserve everything else verbatim.
- Keep the file valid and idiomatic; do not add commentary or explanations.
"""


class CoderAgent:
    def __init__(self, client: MeshClient, repo: str, model: str, prefer: str, name: str = "coder"):
        self.c, self.repo, self.model, self.prefer, self.name = client, repo, model, prefer, name

    def _abs(self, path: str) -> str:
        return path if os.path.isabs(path) else os.path.join(self.repo, path)

    def locate(self, task: str) -> str | None:
        """Use scout (FastContext) to find the target file for the task."""
        ok, data = self.c.scout(task, self.repo)
        if not ok:
            return None
        text = data.get("answer") or data.get("result") or "" if isinstance(data, dict) else str(data)
        cites = data.get("citations") or data.get("files") if isinstance(data, dict) else None
        # Prefer an explicit citation; else the first file-looking path in the text.
        if cites:
            first = cites[0]
            return first.get("path") if isinstance(first, dict) else str(first).split(":")[0]
        import re
        m = re.search(r"[\w./-]+\.(py|md|json|toml|ts|tsx)", text)
        return m.group(0) if m else None

    def run(self, task: str, target: str | None, apply: bool) -> dict:
        print(f"[{self.name}] task: {task}")
        if not target:
            print(f"[{self.name}] asking scout to locate the file...")
            target = self.locate(task)
            if not target:
                return {"agent": self.name, "status": "no_target", "note": "scout found no file"}
            print(f"[{self.name}] scout → {target}")
        path = self._abs(target)

        ok, data = self.c.read_file(path)
        if not ok:
            return {"agent": self.name, "status": "read_failed", "target": target, "error": str(data)[:200]}
        current = data.get("content", "") if isinstance(data, dict) else ""

        prompt = f"TASK:\n{task}\n\nFILE: {target}\n\nCURRENT CONTENTS:\n{current}"
        reply = self.c.chat(self.model,
                            [{"role": "system", "content": CODER_SYS}, {"role": "user", "content": prompt}],
                            prefer=self.prefer, max_tokens=4000)
        proposed = strip_code_fence(reply)
        if not proposed or proposed == current:
            return {"agent": self.name, "status": "no_change", "target": target}

        if not apply:
            return {"agent": self.name, "status": "proposed", "target": target,
                    "diff_chars": len(proposed) - len(current),
                    "preview": proposed[:240]}

        # Governance gate before mutating.
        verdict = self.c.assess("chp.adapters.filesystem.write_file", {"path": path})
        if verdict.get("recommendation") == "block":
            return {"agent": self.name, "status": "blocked_by_safety", "target": target,
                    "level": verdict.get("level")}

        ok, data = self.c.write_file(path, proposed)
        if not ok:
            return {"agent": self.name, "status": "write_failed", "target": target, "error": str(data)[:200]}
        cok, cdata = self.c.conformance(path)
        violations = (cdata.get("violations") if isinstance(cdata, dict) else None) or []
        return {"agent": self.name, "status": "applied", "target": target,
                "safety": verdict.get("level"),
                "conformance": "clean" if cok and not violations else f"{len(violations)} issue(s)"}


def main() -> int:
    ap = argparse.ArgumentParser(description="CHP coding agent on the mesh.")
    ap.add_argument("task")
    ap.add_argument("--file", help="Target file (relative to repo). If omitted, scout locates it.")
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--model", default=os.environ.get("CODER_MODEL", PRIMARY_MODEL))
    ap.add_argument("--prefer", default="primary", help="Node to run the coder model on.")
    ap.add_argument("--apply", action="store_true", help="Write the change (default: propose only).")
    args = ap.parse_args()

    client = MeshClient()
    agent = CoderAgent(client, args.repo, args.model, args.prefer)
    print(f"coder · model={args.model} @{args.prefer} · correlation={client.correlation['correlation_id']}\n")
    result = agent.run(args.task, args.file, args.apply)
    print("\nRESULT:", result)
    client.print_trail()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
