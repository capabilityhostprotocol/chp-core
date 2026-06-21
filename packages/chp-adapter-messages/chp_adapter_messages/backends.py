"""Storage backends for conversation transcripts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class MessageBackend(Protocol):
    async def append(self, session_id: str, turn: dict) -> None: ...
    async def load(self, session_id: str) -> list[dict]: ...
    async def list_sessions(self) -> list[str]: ...


class JSONLBackend:
    """Writes one JSONL file per session under base_dir."""

    def __init__(self, base_dir: str = "~/.chp-agent/messages") -> None:
        self._base = Path(base_dir).expanduser()

    def _path(self, session_id: str) -> Path:
        return self._base / f"{session_id}.jsonl"

    async def append(self, session_id: str, turn: dict) -> None:
        self._base.mkdir(parents=True, exist_ok=True)
        with self._path(session_id).open("a", encoding="utf-8") as f:
            f.write(json.dumps(turn, sort_keys=True) + "\n")

    async def load(self, session_id: str) -> list[dict]:
        path = self._path(session_id)
        if not path.exists():
            return []
        turns: list[dict] = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        turns.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return turns

    async def list_sessions(self) -> list[str]:
        if not self._base.exists():
            return []
        return sorted(
            p.stem for p in self._base.glob("*.jsonl")
        )


class CHPFilesystemBackend:
    """Archives transcript JSONL to a remote CHP host via chp.adapters.filesystem.write_file.

    Uses HttpTransport so no local credentials are required — authentication is
    via the remote host's API key set in remote_host_key.
    """

    def __init__(
        self,
        remote_host_url: str,
        remote_host_key: str | None = None,
        path_template: str = "/volume1/homes/chp/messages/{session_id}.jsonl",
    ) -> None:
        self._url = remote_host_url
        self._key = remote_host_key
        self._path_template = path_template

    def _remote_path(self, session_id: str) -> str:
        return self._path_template.format(session_id=session_id)

    def _transport(self):
        from chp_core.transport import HttpTransport
        return HttpTransport(base_url=self._url, api_key=self._key)

    async def write_session(self, session_id: str, turns: list[dict]) -> str:
        """Write turns as JSONL to the remote CHP host. Returns remote path."""
        remote_path = self._remote_path(session_id)
        content = "\n".join(json.dumps(t, sort_keys=True) for t in turns) + "\n"
        transport = self._transport()
        await transport.invoke(
            "chp.adapters.filesystem.write_file",
            {"path": remote_path, "content": content, "create_parents": True},
        )
        return remote_path

    # Protocol conformance stubs — CHPFilesystemBackend is write-only for now
    async def append(self, session_id: str, turn: dict) -> None:
        raise NotImplementedError("CHPFilesystemBackend is archive-only; use archive_to_remote")

    async def load(self, session_id: str) -> list[dict]:
        raise NotImplementedError("CHPFilesystemBackend is write-only")

    async def list_sessions(self) -> list[str]:
        raise NotImplementedError("CHPFilesystemBackend is write-only")
