"""Local CHP adapter registry (~/.chp/registry.json).

Tracks which adapters are known and enabled. No extra dependencies — uses JSON
consistent with policy.json.

Registry file format (~/.chp/registry.json or .chp/registry.json):
  {
    "version": "1",
    "adapters": [
      {
        "id": "codex",
        "package": "chp-codex",
        "version": ">=1.0.0",
        "enabled": true,
        "tags": ["agentic", "openai"]
      }
    ]
  }
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RegistryEntry:
    id: str
    package: str | None = None
    version: str | None = None
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryEntry":
        return cls(
            id=data["id"],
            package=data.get("package"),
            version=data.get("version"),
            enabled=bool(data.get("enabled", True)),
            tags=list(data.get("tags", [])),
        )


def default_registry_path() -> str:
    """Return the active registry path: project-local if .chp/ exists, otherwise global."""
    env = os.environ.get("CHP_REGISTRY_FILE")
    if env:
        return env
    local = Path(".chp") / "registry.json"
    if local.parent.exists():
        return str(local)
    global_dir = Path.home() / ".chp"
    global_dir.mkdir(parents=True, exist_ok=True)
    return str(global_dir / "registry.json")


def load_registry(path: str | None = None) -> list[RegistryEntry]:
    """Load all entries from the registry file. Returns empty list if file does not exist."""
    registry_path = Path(path or default_registry_path())
    if not registry_path.exists():
        return []
    try:
        with registry_path.open() as f:
            data = json.load(f)
        return [RegistryEntry.from_dict(entry) for entry in data.get("adapters", [])]
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def save_registry(entries: list[RegistryEntry], path: str | None = None) -> None:
    """Write entries to the registry file, creating it if necessary."""
    registry_path = Path(path or default_registry_path())
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": "1",
        "adapters": [e.to_dict() for e in entries],
    }
    registry_path.write_text(json.dumps(data, indent=2))


def add_entry(entry: RegistryEntry, path: str | None = None) -> None:
    """Add or replace an entry by ID (idempotent)."""
    entries = load_registry(path)
    entries = [e for e in entries if e.id != entry.id]
    entries.append(entry)
    save_registry(entries, path)


def remove_entry(adapter_id: str, path: str | None = None) -> bool:
    """Remove an entry by ID. Returns True if it was present, False otherwise."""
    entries = load_registry(path)
    before = len(entries)
    entries = [e for e in entries if e.id != adapter_id]
    if len(entries) == before:
        return False
    save_registry(entries, path)
    return True
