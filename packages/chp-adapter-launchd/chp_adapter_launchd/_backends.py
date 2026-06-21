"""launchd backend — the only file that touches launchctl and the filesystem.

Isolated here (the CLI-adapter convention used by git/radicle/process) so
adapter.py contains no subprocess or file I/O in its capability bodies and stays
conformance-clean. The adapter depends only on the LaunchdBackend protocol.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

_LAUNCHCTL = "/bin/launchctl"
_TIMEOUT = 30.0


@runtime_checkable
class LaunchdBackend(Protocol):
    def list_services(self, prefix: str) -> list[dict]: ...
    def status(self, label: str) -> dict: ...
    def start(self, label: str, plist_path: str | None) -> dict: ...
    def stop(self, label: str) -> dict: ...
    def install(self, label: str, spec: dict) -> dict: ...
    def uninstall(self, label: str) -> dict: ...


def _domain() -> str:
    return f"gui/{os.getuid()}"


def _agents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _plist_path(label: str) -> Path:
    return _agents_dir() / f"{label}.plist"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=_TIMEOUT)


class _RealLaunchdBackend:
    """Wraps launchctl + plistlib for managing user LaunchAgents."""

    def _list_raw(self) -> list[dict]:
        proc = _run([_LAUNCHCTL, "list"])
        services: list[dict] = []
        for line in proc.stdout.splitlines()[1:]:  # skip header "PID Status Label"
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            pid_s, status_s, label = parts
            pid = int(pid_s) if pid_s.lstrip("-").isdigit() and pid_s != "-" else None
            try:
                last_exit = int(status_s)
            except ValueError:
                last_exit = None
            services.append({
                "label": label,
                "pid": pid,
                "running": pid is not None,
                "last_exit_code": last_exit,
            })
        return services

    def list_services(self, prefix: str) -> list[dict]:
        return [s for s in self._list_raw() if s["label"].startswith(prefix)]

    def status(self, label: str) -> dict:
        match = next((s for s in self._list_raw() if s["label"] == label), None)
        plist_exists = _plist_path(label).exists()
        if match is None:
            return {"label": label, "loaded": False, "running": False, "pid": None,
                    "last_exit_code": None, "plist_exists": plist_exists}
        return {"label": label, "loaded": True, "running": match["running"],
                "pid": match["pid"], "last_exit_code": match["last_exit_code"],
                "plist_exists": plist_exists}

    def start(self, label: str, plist_path: str | None) -> dict:
        loaded = any(s["label"] == label for s in self._list_raw())
        if loaded:
            proc = _run([_LAUNCHCTL, "kickstart", "-k", f"{_domain()}/{label}"])
            action = "kickstart"
        else:
            path = plist_path or str(_plist_path(label))
            if not Path(path).exists():
                raise FileNotFoundError(f"No plist for {label!r} at {path}; install it first.")
            proc = _run([_LAUNCHCTL, "bootstrap", _domain(), path])
            action = "bootstrap"
        ok = proc.returncode == 0
        return {"label": label, "action": action, "ok": ok,
                "returncode": proc.returncode, "stderr": proc.stderr.strip()[:300]}

    def stop(self, label: str) -> dict:
        proc = _run([_LAUNCHCTL, "bootout", f"{_domain()}/{label}"])
        return {"label": label, "action": "bootout", "ok": proc.returncode == 0,
                "returncode": proc.returncode, "stderr": proc.stderr.strip()[:300]}

    def install(self, label: str, spec: dict) -> dict:
        program: str = spec["program"]
        args: list[str] = spec.get("args") or []
        plist: dict[str, Any] = {
            "Label": label,
            "ProgramArguments": [program, *args],
            "RunAtLoad": bool(spec.get("run_at_load", True)),
            "KeepAlive": bool(spec.get("keep_alive", True)),
        }
        if spec.get("env"):
            plist["EnvironmentVariables"] = dict(spec["env"])
        if spec.get("working_dir"):
            plist["WorkingDirectory"] = spec["working_dir"]
        if spec.get("stdout_path"):
            plist["StandardOutPath"] = spec["stdout_path"]
        if spec.get("stderr_path"):
            plist["StandardErrorPath"] = spec["stderr_path"]

        _agents_dir().mkdir(parents=True, exist_ok=True)
        path = _plist_path(label)
        with open(path, "wb") as fh:
            plistlib.dump(plist, fh)

        # Re-bootstrap: bootout first if already loaded (ignore failure), then bootstrap.
        _run([_LAUNCHCTL, "bootout", f"{_domain()}/{label}"])
        proc = _run([_LAUNCHCTL, "bootstrap", _domain(), str(path)])
        return {"label": label, "plist_path": str(path), "ok": proc.returncode == 0,
                "returncode": proc.returncode, "stderr": proc.stderr.strip()[:300],
                "env_keys": sorted((spec.get("env") or {}).keys())}

    def uninstall(self, label: str) -> dict:
        boot = _run([_LAUNCHCTL, "bootout", f"{_domain()}/{label}"])
        path = _plist_path(label)
        removed = False
        if path.exists():
            path.unlink()
            removed = True
        return {"label": label, "booted_out": boot.returncode == 0,
                "plist_removed": removed, "plist_path": str(path)}


def make_backend() -> _RealLaunchdBackend:
    return _RealLaunchdBackend()
