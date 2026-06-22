"""Shared mesh-agent plumbing for the CHP-develops-CHP examples.

A thin client over the gateway that:
  - invokes capabilities with a shared correlation id (so a run is replayable),
  - pins each call to a node via `prefer` (model on primary/inference, repo tools
    on the primary),
  - records a governed-call trail,
  - exposes chat() against an MLX model and a few typed tool helpers.
"""

from __future__ import annotations

import json
import os
import re
import uuid

from chp_core.http import RemoteCapabilityHost


def extract_json(text: str) -> dict | None:
    """Find the first balanced {...} object in a model reply (lenient)."""
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


def strip_code_fence(text: str) -> str:
    """Return the body of the first ``` fenced block, or the text unchanged."""
    m = re.search(r"```(?:[a-zA-Z0-9_+-]*)\n(.*?)```", text, re.DOTALL)
    return m.group(1) if m else text.strip()


class MeshClient:
    """Gateway client with correlation, node-affinity, and an evidence trail."""

    def __init__(self, gateway: str | None = None, key: str | None = None,
                 correlation_id: str | None = None, timeout: int = 240):
        gateway = gateway or os.environ.get("CHP_GATEWAY", "http://127.0.0.1:8800")
        key = key or os.environ.get("CHP_GATEWAY_KEY") or os.environ.get("CHP_HOST_API_KEY")
        if not key:
            raise SystemExit("Set CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)")
        self.gw = RemoteCapabilityHost(gateway, api_key=key, timeout=timeout)
        self.correlation = {"correlation_id": correlation_id or f"chp-team-{uuid.uuid4().hex[:8]}"}
        self.trail: list[dict] = []

    def invoke(self, cap: str, payload: dict, prefer: str | None = None) -> tuple[bool, object]:
        meta = {"prefer": prefer} if prefer else {}
        r = self.gw.invoke(cap, payload, correlation=self.correlation, metadata=meta)
        self.trail.append({"cap": cap, "outcome": r.outcome, "prefer": prefer})
        return r.success, (r.data if r.success else (r.error or r.denial))

    # -- typed helpers -------------------------------------------------------

    def chat(self, model: str, messages: list[dict], prefer: str,
             max_tokens: int = 1200, temperature: float = 0.2) -> str:
        ok, data = self.invoke("chp.adapters.mlx.chat",
                               {"model": model, "messages": messages,
                                "max_tokens": max_tokens, "temperature": temperature},
                               prefer=prefer)
        if not ok:
            raise RuntimeError(f"mlx.chat ({prefer}) failed: {data}")
        return (data.get("message") or {}).get("content", "")

    def scout(self, task: str, repo: str) -> tuple[bool, object]:
        # FastContext-backed repo exploration (tool-calling), pinned to the repo node.
        return self.invoke("chp.adapters.scout.query", {"task": task, "repo_path": repo},
                           prefer="primary")

    def read_file(self, path: str) -> tuple[bool, object]:
        return self.invoke("chp.adapters.filesystem.read_file", {"path": path}, prefer="primary")

    def write_file(self, path: str, content: str) -> tuple[bool, object]:
        return self.invoke("chp.adapters.filesystem.write_file",
                           {"path": path, "content": content}, prefer="primary")

    def assess(self, capability_id: str, payload: dict) -> dict:
        ok, data = self.invoke("chp.adapters.safety.assess",
                               {"capability_id": capability_id, "payload": payload},
                               prefer="primary")
        return data if ok and isinstance(data, dict) else {"recommendation": "allow", "level": "unknown"}

    def conformance(self, source_path: str) -> tuple[bool, object]:
        return self.invoke("chp.adapters.conformance.check_source",
                           {"source_path": source_path}, prefer="primary")

    def print_trail(self) -> None:
        print(f"\nevidence: {len(self.trail)} governed calls · correlation "
              f"{self.correlation['correlation_id']}")
        for t in self.trail:
            print(f"  {t['outcome']:8} {t['cap']}" + (f"  (@{t['prefer']})" if t['prefer'] else ""))
