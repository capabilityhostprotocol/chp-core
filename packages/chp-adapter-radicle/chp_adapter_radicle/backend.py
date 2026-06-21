"""RadicleBackend — subprocess wrappers for the ``rad`` CLI and ``git push rad``."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Protocol, runtime_checkable

# Directories where rad is commonly installed outside the default launchd PATH.
_EXTRA_PATH_DIRS = [
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/.cargo/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
]

def _rad_env() -> dict[str, str]:
    """Return an env dict with rad's install dirs prepended to PATH."""
    env = os.environ.copy()
    current = env.get("PATH", "")
    extra = ":".join(d for d in _EXTRA_PATH_DIRS if d not in current)
    env["PATH"] = f"{extra}:{current}" if extra else current
    return env

def _rad_binary() -> str:
    """Locate the rad binary, checking extra dirs if not on default PATH."""
    if shutil.which("rad"):
        return "rad"
    for d in _EXTRA_PATH_DIRS:
        candidate = os.path.join(d, "rad")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "rad"  # let subprocess raise FileNotFoundError with a clear message


@runtime_checkable
class RadicleBackend(Protocol):
    """Minimal interface for running Radicle CLI sub-commands."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        """Run ``rad <args>`` and return stdout. Raises RuntimeError on non-zero exit."""
        ...

    def git_push(self, remote: str, branch: str, cwd: str | None = None) -> str:
        """Run ``git push <remote> <branch>`` and return combined stdout+stderr."""
        ...


class SubprocessRadicleBackend:
    """Production backend: delegates to the ``rad`` binary and ``git``."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        result = subprocess.run(
            [_rad_binary(), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            env=_rad_env(),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"rad {args[0]} failed")
        return result.stdout.strip()

    def git_push(self, remote: str, branch: str, cwd: str | None = None) -> str:
        result = subprocess.run(
            ["git", "push", remote, branch],
            cwd=cwd,
            capture_output=True,
            text=True,
            env=_rad_env(),
        )
        combined = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            raise RuntimeError(combined or f"git push {remote} {branch} failed")
        return combined


class FakeRadicleBackend:
    """Test double: records calls and returns scripted responses."""

    def __init__(
        self,
        responses: dict[tuple, str] | None = None,
        push_responses: dict[tuple, str] | None = None,
        default: str = "",
    ) -> None:
        self._responses = responses or {}
        self._push_responses = push_responses or {}
        self._default = default
        self.calls: list[tuple[str, ...]] = []
        self.push_calls: list[tuple[str, str]] = []

    def run(self, *args: str, cwd: str | None = None) -> str:
        self.calls.append(args)
        return self._responses.get(args, self._default)

    def git_push(self, remote: str, branch: str, cwd: str | None = None) -> str:
        self.push_calls.append((remote, branch))
        key = (remote, branch)
        return self._push_responses.get(key, f"To rad://fake\n * [new branch] {branch} -> {branch}")
