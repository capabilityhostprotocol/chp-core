"""chp-adapter-process — governed subprocess/CLI execution as a CHP capability.

One capability:

* ``run`` — execute a command with args; allowlist + timeout + cwd-root enforcement.
  Returns ``{exit_code, stdout, stderr, timed_out, duration_ms}``.
  Evidence: command/args, env_additions keys (not values), exit code, previews.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_process import ProcessAdapter, ProcessConfig

    host = LocalCapabilityHost()
    register_adapter(host, ProcessAdapter(ProcessConfig(
        allowed_commands=["echo", "ls"],
        max_timeout=10.0,
    )))
"""

from __future__ import annotations

from .adapter import ProcessAdapter, ProcessConfig

__all__ = ["ProcessAdapter", "ProcessConfig"]
