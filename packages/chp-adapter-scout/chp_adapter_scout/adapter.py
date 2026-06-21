"""ScoutAdapter — FastContext repo-exploration subagent as a CHP capability.

Wraps the FastContext-1.0 model (served via vLLM on port 8092) in a governed
multi-turn agentic loop. The frontier model calls this once and gets back compact
file-path citations instead of exploring the repo itself.

Protocol:
  1. Send task + system prompt to FastContext via chp.adapters.http.request
     (OpenAI /v1/chat/completions with tool definitions).
  2. Execute returned tool_calls in parallel via ctx.ainvoke to filesystem caps.
  3. Repeat up to max_turns; stop when model returns a plain text answer.
  4. Parse <final_answer> block → [{path, line_range, note}] citation list.

Evidence policy:
  - task text NOT emitted (may contain sensitive context)
  - Emitted: turns_used, files_cited_count, repo_path, latency_ms, tool_names
  - File content returned by filesystem caps is passed to the model but never
    stored in this adapter's evidence (filesystem caps handle their own evidence)
"""

from __future__ import annotations

import asyncio
import json as _json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chp_core import BaseAdapter, capability

_HTTP_CAP = "chp.adapters.http.request"
_FS_READ = "chp.adapters.filesystem.read_file"
_FS_GLOB = "chp.adapters.filesystem.glob_files"
_FS_GREP = "chp.adapters.filesystem.grep"

_EMITS = [
    "scout_started",
    "scout_tool_call",
    "scout_completed",
    "scout_failed",
]

# FastContext's exact tool schemas (from the model card / github.com/microsoft/fastcontext)
_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file or a range of lines from a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative file path."},
                    "start_line": {"type": "integer", "description": "First line to read (1-indexed, inclusive)."},
                    "end_line": {"type": "integer", "description": "Last line to read (1-indexed, inclusive)."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "glob",
            "description": "Find files matching a glob pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern, e.g. **/*.py"},
                    "path": {"type": "string", "description": "Base directory to search."},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "Search files for a regex pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern to search."},
                    "path": {"type": "string", "description": "Directory or file to search."},
                    "glob": {"type": "string", "description": "File filter glob, e.g. *.py"},
                    "output_mode": {"type": "string", "description": "Output mode (ignored; always returns matches)."},
                },
                "required": ["pattern"],
            },
        },
    },
]

_SYSTEM_PROMPT = (
    "You are a repository scout. Your only job is to locate the exact files and "
    "line ranges that are relevant to the user's task. Use the read_file, glob, and "
    "grep tools to explore the repository. When you have found the relevant locations, "
    "respond with a <final_answer> block containing one citation per line in the format:\n"
    "  /path/to/file.py:start_line-end_line  # optional note\n\n"
    "Be concise. Do not explain the code. Do not fix anything. Only locate it."
)

# Qwen3 emits tool calls as <tool_call>{"name":...,"arguments":{...}}</tool_call>
# when vLLM's streaming parser is not active. Parse them as a fallback.
_TOOL_CALL_XML_RE = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL
)

_FINAL_ANSWER_RE = re.compile(
    r"<final_answer>(.*?)</final_answer>", re.DOTALL | re.IGNORECASE
)
_CITATION_RE = re.compile(
    r"([^\s:]+\.(?:py|ts|js|go|rs|java|c|cpp|h|md|yaml|json|toml))"
    r"(?::(\d+)(?:-(\d+))?)?(?:\s*#\s*(.*))?",
    re.IGNORECASE,
)


@dataclass
class ScoutConfig:
    base_url: str = "http://localhost:8092"
    model: str = "fastcontext"
    max_turns: int = 6
    timeout: float = 30.0


class ScoutAdapter(BaseAdapter):
    """Run a FastContext repo-scout subagent as a governed CHP capability."""

    adapter_id = "chp.adapters.scout"
    adapter_name = "Scout"
    adapter_description = (
        "Repo-exploration subagent powered by FastContext-1.0. Given a task and "
        "repo path, returns compact file:line citations so the frontier model "
        "does not need to explore the repository itself."
    )
    adapter_category = "infrastructure"
    adapter_tags = ["scout", "fastcontext", "agent", "repo", "search"]

    def __init__(self, config: ScoutConfig | None = None) -> None:
        self._config = config or ScoutConfig()

    @capability(
        id="chp.adapters.scout.query",
        version="1.0.0",
        description=(
            "Ask the FastContext scout to locate relevant files for a task. "
            "Returns file:line citations. The frontier model only sees the result, "
            "not the exploration turns."
        ),
        category="infrastructure",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "What to find in the repository (not stored in evidence).",
                },
                "repo_path": {
                    "type": "string",
                    "description": "Absolute path to the repository root.",
                },
                "max_turns": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": "Override max agent turns (default from config).",
                },
            },
            "required": ["task", "repo_path"],
            "additionalProperties": False,
        },
    )
    async def query(self, ctx: Any, payload: dict) -> dict:
        task: str = payload["task"]
        repo_path = str(Path(payload["repo_path"]).resolve())
        max_turns = payload.get("max_turns") or self._config.max_turns

        t0 = time.monotonic()
        ctx.emit("scout_started", {
            "repo_path": repo_path,
            "max_turns": max_turns,
        }, redacted=False)

        messages: list[dict] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Repository: {repo_path}\n\nTask: {task}"},
        ]

        files_cited: list[dict] = []
        turns_used = 0
        _prompt_tokens = 0
        _completion_tokens = 0

        try:
            for turn in range(max_turns):
                turns_used = turn + 1

                # Call FastContext via the http transport
                http_result = await ctx.ainvoke(_HTTP_CAP, {
                    "method": "POST",
                    "url": f"{self._config.base_url}/v1/chat/completions",
                    "json_body": {
                        "model": self._config.model,
                        "messages": messages,
                        "tools": _TOOLS,
                        "tool_choice": "auto",
                    },
                    "timeout": self._config.timeout,
                })

                if not getattr(http_result, "success", False):
                    raise RuntimeError(
                        f"Scout model unreachable: {getattr(http_result, 'error', 'http error')}"
                    )

                _usage = (http_result.data or {}).get("json", {}).get("usage") or {}
                _prompt_tokens += _usage.get("prompt_tokens", 0)
                _completion_tokens += _usage.get("completion_tokens", 0)

                response_json = http_result.data.get("json") or {}
                choice = (response_json.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                tool_calls = message.get("tool_calls") or []
                raw_content = message.get("content") or ""

                # Qwen3 fallback: vLLM qwen3_xml parser only activates for streaming
                # responses. In non-streaming mode the model outputs <tool_call> XML
                # inside content. Parse it into structured tool_calls here.
                if not tool_calls and raw_content:
                    xml_matches = _TOOL_CALL_XML_RE.findall(raw_content)
                    for i, raw_match in enumerate(xml_matches):
                        try:
                            obj = _json.loads(raw_match)
                        except _json.JSONDecodeError:
                            ctx.emit("scout_tool_call", {
                                "turn": turn + 1,
                                "tool_names": ["<xml_parse_error>"],
                            }, redacted=False)
                            continue
                        tool_calls.append({
                            "id": f"call_xml_{turn}_{i}",
                            "type": "function",
                            "function": {
                                "name": obj.get("name", ""),
                                "arguments": _json.dumps(obj.get("arguments", {})),
                            },
                        })

                # Strip <tool_call> XML from content so it's not treated as final answer
                content_clean = _TOOL_CALL_XML_RE.sub("", raw_content).strip()

                # Append assistant message to history
                messages.append({"role": "assistant", **(
                    {"content": content_clean, "tool_calls": tool_calls}
                    if tool_calls else
                    {"content": raw_content}
                )})

                if not tool_calls:
                    # Final answer — parse citations
                    files_cited = _parse_citations(raw_content, repo_path)
                    break

                # Execute tool calls in parallel
                tool_names = [tc.get("function", {}).get("name", "?") for tc in tool_calls]
                ctx.emit("scout_tool_call", {
                    "turn": turn + 1,
                    "tool_names": tool_names,
                }, redacted=False)

                tool_results = await asyncio.gather(*[
                    _execute_tool(ctx, tc, repo_path)
                    for tc in tool_calls
                ], return_exceptions=True)

                for tc, result in zip(tool_calls, tool_results):
                    tc_id = tc.get("id", f"call_{turn}")
                    content = str(result) if isinstance(result, Exception) else result
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": content,
                    })

        except Exception as exc:
            latency_ms = round((time.monotonic() - t0) * 1000)
            ctx.emit("scout_failed", {
                "repo_path": repo_path,
                "turns_used": turns_used,
                "error": str(exc)[:300],
                "latency_ms": latency_ms,
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("scout_completed", {
            "repo_path": repo_path,
            "turns_used": turns_used,
            "files_cited_count": len(files_cited),
            "latency_ms": latency_ms,
            "prompt_tokens": _prompt_tokens,
            "completion_tokens": _completion_tokens,
            "total_tokens": _prompt_tokens + _completion_tokens,
        }, redacted=False)

        return {
            "files": files_cited,
            "files_cited_count": len(files_cited),
            "turns_used": turns_used,
            "latency_ms": latency_ms,
            "prompt_tokens": _prompt_tokens,
            "completion_tokens": _completion_tokens,
            "total_tokens": _prompt_tokens + _completion_tokens,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _execute_tool(ctx: Any, tool_call: dict, repo_path: str) -> str:
    """Map a FastContext tool_call to the appropriate CHP filesystem capability."""
    fn = tool_call.get("function") or {}
    name = fn.get("name", "")
    try:
        args = _json.loads(fn.get("arguments") or "{}")
    except Exception:
        return "error: could not parse tool arguments"

    # Prepend repo_path to any relative path argument
    def _abs(p: str | None) -> str:
        if not p:
            return repo_path
        return p if Path(p).is_absolute() else str(Path(repo_path) / p)

    try:
        if name == "read_file":
            result = await ctx.ainvoke(_FS_READ, {
                "path": _abs(args.get("path")),
            })
            if not getattr(result, "success", False):
                return f"error reading file: {result.error}"
            content: str = result.data.get("content", "")
            # Apply line range if requested
            start = args.get("start_line")
            end = args.get("end_line")
            if start or end:
                lines = content.splitlines()
                s = max(0, (start or 1) - 1)
                e = end if end else len(lines)
                content = "\n".join(
                    f"{s + i + 1}: {line}" for i, line in enumerate(lines[s:e])
                )
            return content or "(empty file)"

        elif name == "glob":
            result = await ctx.ainvoke(_FS_GLOB, {
                "pattern": args.get("pattern", "*"),
                "base_path": _abs(args.get("path")),
            })
            if not getattr(result, "success", False):
                return f"error: {result.error}"
            files = result.data.get("files", [])
            return "\n".join(files) if files else "(no files matched)"

        elif name == "grep":
            payload: dict = {
                "pattern": args.get("pattern", ""),
                "path": _abs(args.get("path")),
            }
            if args.get("glob"):
                payload["glob"] = args["glob"]
            result = await ctx.ainvoke(_FS_GREP, payload)
            if not getattr(result, "success", False):
                return f"error: {result.error}"
            matches = result.data.get("matches", [])
            if not matches:
                return "(no matches)"
            lines = [f"{m['file']}:{m['line_no']}: {m['text']}" for m in matches]
            if result.data.get("truncated"):
                lines.append("... (truncated)")
            # Cap output to avoid overflowing the 8k context of the scout model
            out = "\n".join(lines)
            if len(out) > 4000:
                out = out[:4000] + "\n... (output capped; narrow search with path= or glob=)"
            return out

        else:
            return f"unknown tool: {name}"

    except Exception as exc:
        return f"error executing {name}: {exc}"


def _parse_citations(content: str, repo_path: str) -> list[dict]:
    """Extract file:line citations from a FastContext <final_answer> block."""
    match = _FINAL_ANSWER_RE.search(content)
    text = match.group(1) if match else content

    citations = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _CITATION_RE.search(line)
        if m:
            path, start, end, note = m.group(1), m.group(2), m.group(3), m.group(4)
            if not Path(path).is_absolute():
                path = str(Path(repo_path) / path)
            elif not Path(path).exists():
                # Model output a root-relative path like /packages/... that doesn't
                # exist as an absolute path; resolve under repo_path instead.
                candidate = str(Path(repo_path) / path.lstrip("/"))
                if Path(candidate).exists():
                    path = candidate
            entry: dict = {"path": path}
            if start:
                entry["line_range"] = f"{start}-{end}" if end else start
            if note:
                entry["note"] = note.strip()
            citations.append(entry)

    return citations
