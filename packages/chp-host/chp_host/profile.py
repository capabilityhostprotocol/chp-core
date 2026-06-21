"""Host profiles — declarative descriptions of a real adapter host.

A profile is a small JSON file naming a host and the adapters it should serve::

    {
      "host_id": "cloud-host",
      "bind": "127.0.0.1",
      "port": 8801,
      "store": ".chp/cloud-host.sqlite",
      "adapters": ["aws", "azure", "gcp", "kubernetes"],
      "secrets": ["MY_API_KEY"]
    }

The optional ``secrets`` list names environment variables that the host will
inject from the macOS Keychain (service: ``com.chp.secrets``) before loading
adapters.  This is equivalent to passing ``--secrets-from-keychain NAME``
for each entry, but declared in the profile so plists stay credential-free.

Profiles make it easy to stand up a fleet of differentiated hosts (a cloud host,
a data host, ...) and point a router at all of them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HostProfile:
    host_id: str
    adapters: list[str] = field(default_factory=list)
    bind: str = "127.0.0.1"
    port: int = 8765
    store: str = ".chp/host.sqlite"
    secrets: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "HostProfile":
        if "host_id" not in data:
            raise ValueError("profile must define 'host_id'")
        if not data.get("adapters"):
            raise ValueError("profile must define a non-empty 'adapters' list")
        store_raw = str(data.get("store", f".chp/{data['host_id']}.sqlite"))
        return cls(
            host_id=str(data["host_id"]),
            adapters=[str(a) for a in data["adapters"]],
            bind=str(data.get("bind", "127.0.0.1")),
            port=int(data.get("port", 8765)),
            store=str(Path(store_raw).expanduser()),
            secrets=[str(s) for s in data.get("secrets", [])],
        )

    @classmethod
    def load(cls, path: str | Path) -> "HostProfile":
        raw = json.loads(Path(path).read_text())
        if not isinstance(raw, dict):
            raise ValueError("profile file must contain a JSON object")
        return cls.from_dict(raw)
