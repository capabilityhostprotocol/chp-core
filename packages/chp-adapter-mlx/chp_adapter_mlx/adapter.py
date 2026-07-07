"""MLXAdapter — Apple Silicon native text generation via a local MLX server.

Wraps a local ``mlx_lm.server`` (Apple's MLX framework — the fastest local
inference path on Apple Silicon) as governed CHP capabilities: generate, chat,
list_models, and status. ``mlx_lm.server`` exposes an OpenAI-compatible API
(``/v1/completions``, ``/v1/chat/completions``, ``/v1/models``), so the wire shape
matches the vLLM/local_llm adapters and the gateway can treat MLX as just another
inference owner for capacity-aware routing.

Lego-block composition: this adapter imports NO HTTP library. Every server call
routes through chp.adapters.http via ctx.ainvoke, so HTTP is its own governed
evidence chain and the adapter stays conformance-clean. The ``status`` capability
additionally reports whether the ``mlx`` / ``mlx-lm`` packages are installed on the
host (via importlib, no heavy import) — "is MLX on this machine and serving?"

Evidence policy:
  Emitted: model id, prompt/completion token counts, message count, latency, errors.
  NOT emitted: prompt text, completion text, or chat message content.
"""

from __future__ import annotations

import contextlib
import glob
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "mlx_generate_started",
    "mlx_generate_completed",
    "mlx_generate_failed",
    "mlx_chat_started",
    "mlx_chat_completed",
    "mlx_chat_failed",
    "mlx_models_listed",
    "mlx_status_reported",
    "mlx_finetune_started",
    "mlx_eval_started",
    "mlx_eval_completed",
    "mlx_eval_failed",
    "mlx_server_started",
    "mlx_server_stopped",
]

# mlx_lm.server defaults to :8080, which collides with llama.cpp (probed by the
# local_llm adapter). Default MLX to :8081 and run `mlx_lm.server --port 8081`.
_DEFAULT_BASE_URL = "http://localhost:8081"
_HTTP_CAP = "chp.adapters.http.request"


def _service_safe_env() -> dict[str, str]:
    """Child env safe under launchd/systemd: ensure HOME (HF cache + logs) and a
    full PATH. Mirrors the host adapter's helper."""
    import pwd
    env = dict(os.environ)
    if not env.get("HOME"):
        try:
            env["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
        except Exception:
            env["HOME"] = "/tmp"
    env["PATH"] = (env.get("PATH", "") + ":/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/opt/homebrew/bin").strip(":")
    return env


def _run_dir() -> str:
    d = os.path.join(_service_safe_env()["HOME"], ".chp", "run")
    os.makedirs(d, exist_ok=True)
    return d


def _read_pid(path: str) -> int | None:
    # os.open (not open()) keeps the adapter conformance-clean.
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            data = os.read(fd, 32).decode().strip()
        finally:
            os.close(fd)
        return int(data) if data else None
    except (OSError, ValueError):
        return None


def _write_pid(path: str, pid: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, str(pid).encode())
    finally:
        os.close(fd)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _server_cmd(model: str, port: int, host: str, adapter_path: str | None = None) -> list[str]:
    """Command to launch mlx_lm's OpenAI server. Prefer the console script next to
    the interpreter; fall back to `python -m mlx_lm.server`. --adapter-path serves a
    LoRA on top of the base model (the flywheel's tuned variant)."""
    script = os.path.join(os.path.dirname(sys.executable), "mlx_lm.server")
    base = [script] if os.path.exists(script) else [sys.executable, "-m", "mlx_lm.server"]
    cmd = base + ["--model", model, "--port", str(port), "--host", host]
    if adapter_path:
        cmd += ["--adapter-path", adapter_path]
    return cmd


def _lora_cmd(model: str, data: str, adapter_path: str, iters: int,
              batch_size: int, num_layers: int | None) -> list[str]:
    """`mlx_lm.lora --train` command — LoRA fine-tune on-fleet (the flywheel's C3).
    *data* is a dir with train.jsonl / valid.jsonl (chat or completions format)."""
    script = os.path.join(os.path.dirname(sys.executable), "mlx_lm.lora")
    base = [script] if os.path.exists(script) else [sys.executable, "-m", "mlx_lm.lora"]
    cmd = base + ["--model", model, "--train", "--data", data, "--adapter-path", adapter_path,
                  "--iters", str(iters), "--batch-size", str(batch_size)]
    if num_layers:
        cmd += ["--num-layers", str(num_layers)]
    return cmd


def _jsonl(content: Any) -> str:
    """Coerce inline dataset content to JSONL text: pass a JSONL string through, or
    serialize a list of records (dicts)."""
    if isinstance(content, str):
        return content if content.endswith("\n") else content + "\n"
    return "".join(json.dumps(r) + "\n" for r in (content or []))


def _materialize_dataset(name: str, train: Any, valid: Any) -> str:
    """Write inline train/valid content into a fresh data dir *on this node* and
    return its path. The finetune node has no process.run and its filesystem
    adapter won't mkdir — but this adapter is Python on that node, so it creates
    its own dataset dir. Solves the cross-node data problem (data + compute must be
    co-located; capacity routing can split them across hosts)."""
    base = os.path.join(_service_safe_env()["HOME"], ".chp", "flywheel-data", name)
    os.makedirs(base, exist_ok=True)
    for fname, content in (("train.jsonl", train), ("valid.jsonl", valid)):
        if content is None:
            continue
        with open(os.path.join(base, fname), "w") as f:
            f.write(_jsonl(content))
    return base


def _stop_all_mlx_servers() -> list[dict]:
    """SIGTERM every tracked mlx_lm server and clear its pidfile — free the GPU
    before training. A served model and LoRA training cannot share a single-GPU
    Apple Silicon node (Metal OOMs after the first iter). Returns what was stopped
    so the caller can re-serve (e.g. with the freshly tuned adapter)."""
    stopped: list[dict] = []
    for pidfile in glob.glob(os.path.join(_run_dir(), "mlx-server-*.pid")):
        pid = _read_pid(pidfile)
        port = os.path.basename(pidfile)[len("mlx-server-"):-len(".pid")]
        if pid and _alive(pid):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
            stopped.append({"pid": pid, "port": port})
        with contextlib.suppress(OSError):
            os.remove(pidfile)
    return stopped


def _tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (s or "").lower())


def _score_one(completion: str, reference: str, metric: str) -> float:
    """Deterministic score of a completion against a reference in [0,1]. `contains`
    = reference substring present; `f1` = token-overlap F1. Text is scored on-node and
    never recorded — only the resulting score lands in evidence."""
    if metric == "contains":
        ref = (reference or "").strip().lower()
        return 1.0 if ref and ref in (completion or "").lower() else 0.0
    c, r = _tokens(completion), _tokens(reference)
    if not c or not r:
        return 0.0
    overlap = sum((Counter(c) & Counter(r)).values())
    if not overlap:
        return 0.0
    prec, rec = overlap / len(c), overlap / len(r)
    return round(2 * prec * rec / (prec + rec), 4)


def _pkg_version(name: str) -> str | None:
    """Installed version of *name*, or None — without importing the package."""
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version(name)
        except PackageNotFoundError:
            return None
    except Exception:
        return None


@dataclass
class MLXConfig:
    base_url: str = ""
    api_key: str = ""
    default_model: str = ""
    timeout: float = 120.0

    def resolved_base_url(self) -> str:
        return self.base_url or os.environ.get("MLX_BASE_URL", _DEFAULT_BASE_URL)

    def resolved_api_key(self) -> str:
        # mlx_lm.server accepts any key; allow override for secured deployments.
        return self.api_key or os.environ.get("MLX_API_KEY", "EMPTY")

    def resolved_default_model(self) -> str:
        return self.default_model or os.environ.get("MLX_MODEL", "")


class MLXAdapter(BaseAdapter):
    """Apple Silicon native generation via a local mlx_lm OpenAI-compatible server."""

    adapter_id = "chp.adapters.mlx"
    adapter_name = "MLX"
    adapter_description = (
        "Text generation and chat from a local mlx_lm.server (Apple Silicon / MLX), "
        "composed through chp.adapters.http as governed CHP capabilities."
    )
    adapter_category = "ai"
    adapter_tags = ["mlx", "generation", "chat", "metal", "apple-silicon", "openai", "local"]

    def __init__(self, config: MLXConfig | None = None) -> None:
        self._config = config or MLXConfig()

    # ------------------------------------------------------------------
    # HTTP composition through the multi-capability router
    # ------------------------------------------------------------------

    async def _http(self, ctx: Any, method: str, path: str, json_body: Any | None = None) -> dict:
        base = self._config.resolved_base_url().rstrip("/")
        req: dict[str, Any] = {"method": method, "url": f"{base}{path}", "timeout": self._config.timeout}
        if json_body is not None:
            req["json_body"] = json_body
        api_key = self._config.resolved_api_key()
        if api_key:
            req["headers"] = {"Authorization": f"Bearer {api_key}"}

        result = await ctx.ainvoke(_HTTP_CAP, req)
        if not result.success:
            raise RuntimeError(
                f"MLX {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            raise RuntimeError(f"MLX {method} {path} returned HTTP {status}")
        return data

    def _model(self, payload: dict) -> str:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no default_model configured (set MLX_MODEL).")
        return model

    # ------------------------------------------------------------------
    # generate
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.generate",
        version="1.0.0",
        description=(
            "Single-turn text completion via a local mlx_lm server (OpenAI /v1/completions), "
            "composed through chp.adapters.http. Prompt and completion text are never recorded in evidence."
        ),
        category="ai",
        provider="mlx",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Model id served by mlx_lm (defaults to configured model)"},
                "prompt": {"type": "string", "minLength": 1},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192, "default": 256},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0, "default": 0.7},
                "top_p": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "stop": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    )
    async def generate(self, ctx: Any, payload: dict) -> dict:
        model = self._model(payload)
        body: dict[str, Any] = {
            "model": model,
            "prompt": payload["prompt"],
            "max_tokens": payload.get("max_tokens", 256),
            "temperature": payload.get("temperature", 0.7),
        }
        if "top_p" in payload:
            body["top_p"] = payload["top_p"]
        if payload.get("stop"):
            body["stop"] = payload["stop"]

        ctx.emit("mlx_generate_started", {"model": model, "max_tokens": body["max_tokens"]}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/completions", body)
        except Exception as exc:
            ctx.emit("mlx_generate_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("mlx_generate_completed", {
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "finish_reason": choice.get("finish_reason"),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "text": choice.get("text", ""),
            "finish_reason": choice.get("finish_reason"),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # chat
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.chat",
        version="1.0.0",
        description=(
            "Multi-turn chat via a local mlx_lm server (OpenAI /v1/chat/completions), composed "
            "through chp.adapters.http. Message content is never recorded in evidence."
        ),
        category="ai",
        provider="mlx",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "messages": {
                    "type": "array",
                    "items": {
                        # Permissive to support OpenAI tool-calling turns: 'tool' role
                        # (tool results), assistant messages with tool_calls (content
                        # null), tool_call_id/name. Forwarded verbatim to the server.
                        "type": "object",
                        "properties": {
                            "role": {"type": "string", "enum": ["system", "user", "assistant", "tool"]},
                            "content": {"type": ["string", "null"]},
                        },
                        "required": ["role"],
                        "additionalProperties": True,
                    },
                    "minItems": 1,
                },
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 8192, "default": 256},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0, "default": 0.7},
                "top_p": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "tools": {"type": "array", "items": {"type": "object"},
                          "description": "OpenAI-format tool definitions to forward to the server (enables tool-calling through the mesh; never recorded in evidence)."},
                "tool_choice": {"description": "OpenAI tool_choice: 'auto' | 'none' | 'required' | {type, function}."},
            },
            "required": ["messages"],
            "additionalProperties": False,
        },
    )
    async def chat(self, ctx: Any, payload: dict) -> dict:
        model = self._model(payload)
        messages: list[dict] = payload["messages"]
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": payload.get("max_tokens", 256),
            "temperature": payload.get("temperature", 0.7),
        }
        if "top_p" in payload:
            body["top_p"] = payload["top_p"]
        if payload.get("tools"):
            body["tools"] = payload["tools"]
        if payload.get("tool_choice") is not None:
            body["tool_choice"] = payload["tool_choice"]

        ctx.emit("mlx_chat_started", {
            "model": model, "message_count": len(messages),
            "tool_count": len(payload.get("tools") or []),
        }, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/v1/chat/completions", body)
        except Exception as exc:
            ctx.emit("mlx_chat_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        resp = data.get("json") or {}
        choice = (resp.get("choices") or [{}])[0]
        usage = resp.get("usage") or {}
        latency_ms = round((time.monotonic() - t0) * 1000)
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        ctx.emit("mlx_chat_completed", {
            "model": model,
            "message_count": len(messages),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "finish_reason": choice.get("finish_reason"),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "message": choice.get("message", {}),
            "finish_reason": choice.get("finish_reason"),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # list_models
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.list_models",
        version="1.0.0",
        description="List models served by the local mlx_lm server (OpenAI /v1/models), via chp.adapters.http.",
        category="ai",
        provider="mlx",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def list_models(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        data = await self._http(ctx, "GET", "/v1/models")
        latency_ms = round((time.monotonic() - t0) * 1000)

        resp = data.get("json") or {}
        models = [{"id": m.get("id"), "owned_by": m.get("owned_by")} for m in (resp.get("data") or [])]
        ctx.emit("mlx_models_listed", {"model_count": len(models), "latency_ms": latency_ms}, redacted=False)
        return {"models": models, "model_count": len(models), "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # status — "is MLX on this machine and serving?"
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.status",
        version="1.0.0",
        description=(
            "Report MLX availability on this host: whether the mlx / mlx-lm packages are "
            "installed (and their versions) and whether the local mlx_lm server is reachable. "
            "Low-risk introspection — makes no inference."
        ),
        category="ai",
        provider="mlx",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def status(self, ctx: Any, payload: dict) -> dict:
        # Package availability — importlib.util.find_spec does not import the package.
        mlx_installed = importlib.util.find_spec("mlx") is not None
        mlx_lm_installed = importlib.util.find_spec("mlx_lm") is not None
        base_url = self._config.resolved_base_url()

        server_healthy = False
        model_count = 0
        models: list[dict] = []
        latency_ms: int | None = None
        server_error: str | None = None

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "GET", "/v1/models")
            latency_ms = round((time.monotonic() - t0) * 1000)
            resp = data.get("json") or {}
            models = [{"id": m.get("id"), "owned_by": m.get("owned_by")} for m in (resp.get("data") or [])]
            model_count = len(models)
            server_healthy = True
        except Exception as exc:
            server_error = str(exc)[:300]

        result = {
            "mlx_installed": mlx_installed,
            "mlx_version": _pkg_version("mlx"),
            "mlx_lm_installed": mlx_lm_installed,
            "mlx_lm_version": _pkg_version("mlx-lm"),
            "server_url": base_url,
            "server_healthy": server_healthy,
            "model_count": model_count,
            "models": models,
            "default_model": self._config.resolved_default_model() or None,
            "latency_ms": latency_ms,
            "server_error": server_error,
        }
        ctx.emit("mlx_status_reported", {
            "mlx_installed": mlx_installed,
            "mlx_lm_installed": mlx_lm_installed,
            "server_healthy": server_healthy,
            "model_count": model_count,
        }, redacted=False)
        return result

    # ------------------------------------------------------------------
    # start_server / stop_server — manage the mlx_lm inference server
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.start_server",
        version="1.0.0",
        description=(
            "Start a local mlx_lm OpenAI server for a model, detached (survives this "
            "host), logging to ~/.chp/logs/mlx-server-<port>.log. The model downloads "
            "on first load. Idempotent: a server already running on the port is left as-is."
        ),
        category="ai",
        provider="mlx",
        risk="high",
        side_effects=["process_spawn"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "MLX model repo (defaults to MLX_MODEL)."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8081},
                "host": {"type": "string", "default": "127.0.0.1"},
                "adapter_path": {"type": "string", "description": "Serve a LoRA adapter on top of the base model (the flywheel's tuned variant)."},
            },
            "additionalProperties": False,
        },
    )
    async def start_server(self, ctx: Any, payload: dict) -> dict:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no MLX_MODEL configured.")
        # Remember the served model as this adapter's default, so subsequent
        # generate/chat calls need not repeat it (for the life of this process).
        self._config.default_model = model
        port = int(payload.get("port") or 8081)
        host = str(payload.get("host") or "127.0.0.1")
        adapter_path = payload.get("adapter_path") or None
        pidfile = os.path.join(_run_dir(), f"mlx-server-{port}.pid")

        existing = _read_pid(pidfile)
        if existing and _alive(existing):
            ctx.emit("mlx_server_started", {"port": port, "pid": existing, "already_running": True}, redacted=False)
            return {"started": False, "already_running": True, "pid": existing, "port": port, "model": model}

        env = _service_safe_env()
        log_dir = os.path.join(env["HOME"], ".chp", "logs")
        os.makedirs(log_dir, exist_ok=True)
        fd = os.open(os.path.join(log_dir, f"mlx-server-{port}.log"),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            proc = subprocess.Popen(_server_cmd(model, port, host, adapter_path),
                                    stdout=fd, stderr=fd, start_new_session=True, env=env)
        finally:
            os.close(fd)
        _write_pid(pidfile, proc.pid)
        ctx.emit("mlx_server_started", {"model": model, "port": port, "pid": proc.pid}, redacted=False)
        return {
            "started": True,
            "pid": proc.pid,
            "port": port,
            "model": model,
            "note": "Loads weights (downloads on first run) then serves; poll chp.adapters.mlx.status.",
        }

    @capability(
        id="chp.adapters.mlx.stop_server",
        version="1.0.0",
        description="Stop the local mlx_lm server running on a port (SIGTERM the tracked pid).",
        category="ai",
        provider="mlx",
        risk="high",
        side_effects=["process_kill"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8081}},
            "additionalProperties": False,
        },
    )
    async def stop_server(self, ctx: Any, payload: dict) -> dict:
        port = int(payload.get("port") or 8081)
        pidfile = os.path.join(_run_dir(), f"mlx-server-{port}.pid")
        pid = _read_pid(pidfile)
        if not pid or not _alive(pid):
            return {"stopped": False, "running": False, "port": port}
        os.kill(pid, signal.SIGTERM)
        with contextlib.suppress(OSError):
            os.remove(pidfile)
        ctx.emit("mlx_server_stopped", {"port": port, "pid": pid}, redacted=False)
        return {"stopped": True, "pid": pid, "port": port}

    # ------------------------------------------------------------------
    # finetune — on-fleet LoRA (the recursive flywheel's training step)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.finetune",
        version="1.0.0",
        description=(
            "LoRA fine-tune a model on-fleet via mlx_lm.lora, detached (logs to "
            "~/.chp/logs/mlx-finetune-<name>.log). Provide the dataset inline via "
            "*train*/*valid* (JSONL string or list of records) — the node writes its "
            "own data dir, so data and compute stay co-located — or point *data* at a "
            "pre-staged dir with train.jsonl / valid.jsonl. By default frees the GPU "
            "first (stops any served model; a served model + training OOM a single-GPU "
            "node). Produces a LoRA at adapter_path that mlx.start_server serves via "
            "--adapter-path. The training step of the evidence→tune→serve flywheel."
        ),
        category="ai",
        provider="mlx",
        risk="high",
        side_effects=["process_spawn", "model_training", "process_kill"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Base model to fine-tune (defaults to MLX_MODEL)."},
                "train": {"type": ["string", "array"], "description": "Inline training data: JSONL string or list of records (mlx_lm chat/completions format). Materialized on the node."},
                "valid": {"type": ["string", "array"], "description": "Inline validation data (same shape as train)."},
                "data": {"type": "string", "description": "Alternative to train/valid: a pre-staged dir with train.jsonl / valid.jsonl."},
                "adapter_path": {"type": "string", "description": "Output directory for the LoRA adapter."},
                "iters": {"type": "integer", "minimum": 1, "maximum": 100000, "default": 300},
                "batch_size": {"type": "integer", "minimum": 1, "maximum": 64, "default": 4},
                "num_layers": {"type": "integer", "minimum": 1, "description": "LoRA layers (default: mlx_lm default)."},
                "free_gpu": {"type": "boolean", "default": True, "description": "Stop any served mlx model before training to avoid GPU OOM."},
            },
            "required": ["adapter_path"],
            "additionalProperties": False,
        },
    )
    async def finetune(self, ctx: Any, payload: dict) -> dict:
        model = payload.get("model") or self._config.resolved_default_model()
        if not model:
            raise ValueError("No model specified and no MLX_MODEL configured.")
        adapter_path = str(payload["adapter_path"])
        iters = int(payload.get("iters") or 300)
        batch_size = int(payload.get("batch_size") or 4)
        num_layers = payload.get("num_layers")
        name = os.path.basename(adapter_path.rstrip("/")) or "lora"

        # Dataset: inline train/valid (materialized on this node) or a pre-staged dir.
        train = payload.get("train")
        valid = payload.get("valid")
        if train is not None or valid is not None:
            data = _materialize_dataset(name, train, valid)
        elif payload.get("data"):
            data = str(payload["data"])
        else:
            raise ValueError("finetune needs inline `train`/`valid` content or a `data` directory.")

        # Free the GPU: a served model and LoRA training cannot share a single-GPU node.
        freed = _stop_all_mlx_servers() if payload.get("free_gpu", True) else []

        env = _service_safe_env()
        log_dir = os.path.join(env["HOME"], ".chp", "logs")
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(adapter_path, exist_ok=True)
        pidfile = os.path.join(_run_dir(), f"mlx-finetune-{name}.pid")
        fd = os.open(os.path.join(log_dir, f"mlx-finetune-{name}.log"),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            proc = subprocess.Popen(
                _lora_cmd(model, data, adapter_path, iters, batch_size, num_layers),
                stdout=fd, stderr=fd, start_new_session=True, env=env)
        finally:
            os.close(fd)
        _write_pid(pidfile, proc.pid)
        ctx.emit("mlx_finetune_started",
                 {"model": model, "iters": iters, "adapter_path": adapter_path,
                  "pid": proc.pid, "freed_servers": len(freed)}, redacted=False)
        note = ("LoRA training runs detached; tail ~/.chp/logs/mlx-finetune-"
                f"{name}.log. When done, serve with mlx.start_server adapter_path=" + adapter_path)
        if freed:
            note += f" (freed {len(freed)} served model(s) for GPU headroom — re-serve after)"
        return {
            "started": True,
            "pid": proc.pid,
            "model": model,
            "adapter_path": adapter_path,
            "data": data,
            "iters": iters,
            "freed_servers": freed,
            "note": note,
        }

    # ------------------------------------------------------------------
    # eval — the flywheel's promotion gate (score the currently-served model)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.mlx.eval",
        version="1.0.0",
        description=(
            "Evaluate the currently-served model against a held-out eval set: generate a "
            "completion per example and score it against a reference (deterministic "
            "token-F1 or substring). Returns the aggregate mean + per-example scores. "
            "Scores only in evidence — prompt/reference/completion text is never recorded. "
            "The flywheel's promotion gate: eval base, swap in the tuned adapter, eval "
            "again, and promote only if the tuned mean wins by a margin."
        ),
        category="ai",
        provider="mlx",
        risk="medium",
        side_effects=["llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Defaults to the served default model."},
                "eval_set": {
                    "type": "array", "minItems": 1,
                    "description": "Held-out examples; each has `prompt` (or `messages`) and a `reference` answer.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "prompt": {"type": "string"},
                            "messages": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                            "reference": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                },
                "metric": {"type": "string", "enum": ["f1", "contains"], "default": "f1"},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 4096, "default": 256},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0, "default": 0.0},
            },
            "required": ["eval_set"],
            "additionalProperties": False,
        },
    )
    async def evaluate(self, ctx: Any, payload: dict) -> dict:
        model = self._model(payload)
        items: list[dict] = payload["eval_set"]
        metric = payload.get("metric", "f1")
        max_tokens = int(payload.get("max_tokens") or 256)
        temperature = float(payload.get("temperature", 0.0))

        ctx.emit("mlx_eval_started", {"model": model, "n": len(items), "metric": metric}, redacted=False)
        t0 = time.monotonic()
        scores: list[float] = []
        predictions: list[str] = []
        references: list[str] = []
        try:
            for ex in items:
                msgs = ex.get("messages") or [{"role": "user", "content": ex.get("prompt", "")}]
                body = {"model": model, "messages": msgs, "max_tokens": max_tokens, "temperature": temperature}
                data = await self._http(ctx, "POST", "/v1/chat/completions", body)
                resp = data.get("json") or {}
                choice = (resp.get("choices") or [{}])[0]
                completion = (choice.get("message") or {}).get("content") or ""
                ref = ex.get("reference", "")
                predictions.append(completion)
                references.append(ref)
                scores.append(_score_one(completion, ref, metric))
        except Exception as exc:
            ctx.emit("mlx_eval_failed", {"model": model, "error": str(exc)[:300]}, redacted=False)
            raise

        mean = round(sum(scores) / len(scores), 4) if scores else 0.0
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("mlx_eval_completed",
                 {"model": model, "n": len(scores), "mean_score": mean, "metric": metric,
                  "latency_ms": latency_ms}, redacted=False)
        # predictions/references are returned (NOT evidenced) so a caller can re-score with any
        # metric — e.g. flywheel.evaluate_and_gate scoring via chp.adapters.huggingface.evaluate.
        return {"model": model, "n": len(scores), "metric": metric,
                "mean_score": mean, "scores": scores, "latency_ms": latency_ms,
                "predictions": predictions, "references": references}
