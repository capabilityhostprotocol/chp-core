"""ProcessAdapter — governed subprocess/CLI execution as a CHP capability.

Safety invariants (MUST PRESERVE):
* ``shell=False`` always — prevents shell injection via args.
* Command must be in ``allowed_commands`` if the list is non-None.
* ``cwd`` must resolve under ``working_dir`` if one is configured.
* Timeout enforced; process killed (SIGKILL) on expiry.
* ``env_additions`` keys in evidence, values never (may carry secrets).
* Full stdout/stderr returned as data; only 500-char previews in evidence.

One capability: ``run``
"""

from __future__ import annotations

import asyncio
import os
import time as _time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = ["process_start", "process_result", "process_timeout", "process_error"]

_PREVIEW_LEN = 500


def _is_within(path: Path, root: Path) -> bool:
    """True if *path* is *root* or lives under it — component-wise, not string
    prefix (so 'working_dir-evil' is not 'within' 'working_dir')."""
    try:
        return path == root or path.is_relative_to(root)
    except AttributeError:  # Python < 3.9
        try:
            return os.path.commonpath([str(path), str(root)]) == str(root)
        except ValueError:
            return False


@dataclass
class ProcessConfig:
    """Config for ProcessAdapter.

    ``allowed_commands`` — if non-None, only these command names (no path
    required) may be executed. Pass ``None`` to allow all (use carefully).

    ``working_dir`` — if set, ``cwd`` in payloads must resolve under this
    root. Defaults to no restriction.

    ``max_timeout`` — hard upper bound on any per-call ``timeout`` value.
    """

    allowed_commands: list[str] | None = None
    working_dir: str | None = None
    max_timeout: float = 60.0
    max_output_bytes: int = 64 * 1024


class ProcessAdapter(BaseAdapter):
    """Governed subprocess/CLI execution."""

    adapter_id = "chp.adapters.process"
    adapter_name = "Process"
    adapter_description = "Execute CLI commands with governed allowlist and timeout enforcement."
    adapter_category = "execution"
    adapter_tags = ["process", "subprocess", "cli", "execution"]

    def __init__(self, config: ProcessConfig | None = None) -> None:
        self._config = config or ProcessConfig()

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.process.run",
        version="1.0.0",
        description="Execute a CLI command with arguments.",
        category="execution",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to execute (no shell)."},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command-line arguments.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory (must be under working_dir if configured).",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (capped at max_timeout).",
                },
                "env_additions": {
                    "type": "object",
                    "description": "Additional environment variables (keys in evidence, values not).",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["process", "cli"],
    )
    async def run(self, ctx: Any, payload: dict) -> dict:
        command = payload["command"]
        args = payload.get("args") or []
        cwd_raw = payload.get("cwd")
        timeout = min(
            float(payload.get("timeout") or self._config.max_timeout),
            self._config.max_timeout,
        )
        env_additions = payload.get("env_additions") or {}

        # --- allowlist check ---
        cfg = self._config
        if cfg.allowed_commands is not None and command not in cfg.allowed_commands:
            ctx.emit("process_error", {
                "reason": "command_not_allowed",
                "command": command,
            }, redacted=False)
            raise PermissionError(f"Command {command!r} is not in allowed_commands")

        # --- cwd check ---
        cwd: str | None = None
        if cwd_raw is not None:
            resolved_cwd = Path(cwd_raw).resolve()
            if cfg.working_dir is not None:
                working_root = Path(cfg.working_dir).resolve()
                # Component-wise containment, not string prefix: a sibling like
                # 'working_dir-evil' must not pass as inside 'working_dir'.
                if not _is_within(resolved_cwd, working_root):
                    ctx.emit("process_error", {
                        "reason": "cwd_outside_working_dir",
                        "cwd": str(resolved_cwd),
                    }, redacted=False)
                    raise PermissionError(
                        f"cwd {resolved_cwd} is outside working_dir {cfg.working_dir!r}"
                    )
            cwd = str(resolved_cwd)

        # --- environment ---
        env = dict(os.environ)
        if env_additions:
            env.update(env_additions)

        ctx.emit("process_start", {
            "command": command,
            "args": args,
            "cwd": cwd,
            "timeout": timeout,
            "env_additions_keys": sorted(env_additions.keys()),
            # env_additions values intentionally not recorded
        }, redacted=False)

        t0 = _time.monotonic()
        timed_out = False
        stdout_str = ""
        stderr_str = ""
        exit_code = -1

        try:
            proc = await asyncio.create_subprocess_exec(
                command, *args,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                exit_code = proc.returncode if proc.returncode is not None else -1
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.communicate()
                exit_code = -1

        except FileNotFoundError:
            duration_ms = int((_time.monotonic() - t0) * 1000)
            ctx.emit("process_error", {
                "command": command,
                "reason": "command_not_found",
                "duration_ms": duration_ms,
            }, redacted=False)
            raise

        except Exception as exc:
            duration_ms = int((_time.monotonic() - t0) * 1000)
            ctx.emit("process_error", {
                "command": command,
                "reason": type(exc).__name__,
                "error": str(exc)[:200],
                "duration_ms": duration_ms,
            }, redacted=False)
            raise

        duration_ms = int((_time.monotonic() - t0) * 1000)

        if not timed_out:
            stdout_bytes = raw_stdout or b""
            stderr_bytes = raw_stderr or b""
            # Truncate to max_output_bytes before decoding
            if len(stdout_bytes) > cfg.max_output_bytes:
                stdout_bytes = stdout_bytes[: cfg.max_output_bytes]
            if len(stderr_bytes) > cfg.max_output_bytes:
                stderr_bytes = stderr_bytes[: cfg.max_output_bytes]
            stdout_str = stdout_bytes.decode(errors="replace")
            stderr_str = stderr_bytes.decode(errors="replace")

        if timed_out:
            ctx.emit("process_timeout", {
                "command": command,
                "timeout": timeout,
                "duration_ms": duration_ms,
            }, redacted=False)
        else:
            ctx.emit("process_result", {
                "command": command,
                "exit_code": exit_code,
                "stdout_preview": stdout_str[:_PREVIEW_LEN],
                "stderr_preview": stderr_str[:_PREVIEW_LEN],
                "duration_ms": duration_ms,
            }, redacted=False)

        return {
            "exit_code": exit_code,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
        }
