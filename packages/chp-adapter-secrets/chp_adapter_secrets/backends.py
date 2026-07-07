"""Secrets backends: MemoryBackend, EnvBackend, FileBackend, KeychainBackend."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretsBackend(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> bool: ...
    def list_keys(self) -> list[str]: ...


class MemoryBackend:
    """In-process dict backend — default for tests and ephemeral use."""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._store: dict[str, str] = dict(initial or {})

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value

    def delete(self, key: str) -> bool:
        if key in self._store:
            del self._store[key]
            return True
        return False

    def list_keys(self) -> list[str]:
        return sorted(self._store.keys())


class EnvBackend:
    """Reads and writes secrets via os.environ.

    Useful for agents that run in environments where secrets are injected
    as environment variables (containers, Lambda, etc.).
    """

    def get(self, key: str) -> str | None:
        return os.environ.get(key)

    def set(self, key: str, value: str) -> None:
        os.environ[key] = value

    def delete(self, key: str) -> bool:
        if key in os.environ:
            del os.environ[key]
            return True
        return False

    def list_keys(self) -> list[str]:
        return sorted(os.environ.keys())


class FileBackend:
    """Reads secrets from a JSON file (``{"KEY": "value", ...}``).

    Supports optional writes; set ``read_only=True`` to prevent mutation.
    The file is loaded once at construction and re-saved on each write.
    """

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._path = Path(path)
        self._read_only = read_only
        self._data: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            # Plaintext secrets at rest must not be group/world-readable.
            # Tighten perms on any pre-existing loose file we encounter.
            try:
                if (self._path.stat().st_mode & 0o077) != 0:
                    os.chmod(self._path, 0o600)
            except OSError:
                pass
            with open(self._path) as fh:
                self._data = json.load(fh)

    def _save(self) -> None:
        # Create with 0600 from the start (umask can't loosen an explicit
        # open-flags mode); never leave a window where secrets are 0644.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(self._data, fh, indent=2)
        os.chmod(self._path, 0o600)

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        if self._read_only:
            raise PermissionError("FileBackend is read-only")
        self._data[key] = value
        self._save()

    def delete(self, key: str) -> bool:
        if self._read_only:
            raise PermissionError("FileBackend is read-only")
        if key in self._data:
            del self._data[key]
            self._save()
            return True
        return False

    def list_keys(self) -> list[str]:
        return sorted(self._data.keys())


class KeychainBackend:
    """macOS Keychain backend via the system ``security`` CLI.

    All CHP secrets use service label ``com.chp.secrets`` with account = key name.
    A small index file (default ``~/.chp/keychain-index.json``) tracks key names
    for ``list_keys()``, because the ``security`` CLI has no bulk-enumerate API.

    Evidence hygiene: secret values are NEVER stored in the index file or emitted
    in evidence — only key names appear.

    Raises ``OSError`` on non-macOS platforms at construction time.
    """

    _SERVICE = "com.chp.secrets"

    def __init__(self, index_path: str | Path | None = None) -> None:
        import platform
        if platform.system() != "Darwin":
            raise OSError("KeychainBackend requires macOS")
        self._index = Path(index_path or Path.home() / ".chp" / "keychain-index.json")

    def _security(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["security", *args], capture_output=True, text=True, input=stdin)

    def _load_index(self) -> list[str]:
        if self._index.exists():
            try:
                return json.loads(self._index.read_text())
            except Exception:
                return []
        return []

    def _save_index(self, keys: list[str]) -> None:
        self._index.parent.mkdir(parents=True, exist_ok=True)
        self._index.write_text(json.dumps(sorted(set(keys)), indent=2))

    def get(self, key: str) -> str | None:
        r = self._security("find-generic-password", "-a", key, "-s", self._SERVICE, "-w")
        if r.returncode != 0:
            return None
        value = r.stdout.strip()
        return value if value else None

    def set(self, key: str, value: str) -> None:
        # -U: update if the item already exists (macOS 10.9+). Pass the secret
        # via stdin (security prompts twice) rather than as a `-w <value>` argv,
        # which would expose it in `ps`/`/proc/<pid>/cmdline` to any local user.
        r = self._security(
            "add-generic-password", "-U", "-a", key, "-s", self._SERVICE, "-w",
            stdin=f"{value}\n{value}\n",
        )
        if r.returncode != 0:
            raise RuntimeError(f"Keychain set failed for {key!r}: {r.stderr.strip()}")
        keys = self._load_index()
        if key not in keys:
            keys.append(key)
            self._save_index(keys)

    def delete(self, key: str) -> bool:
        r = self._security("delete-generic-password", "-a", key, "-s", self._SERVICE)
        if r.returncode != 0:
            return False
        keys = self._load_index()
        self._save_index([k for k in keys if k != key])
        return True

    def list_keys(self) -> list[str]:
        return self._load_index()
