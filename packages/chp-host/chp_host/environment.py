"""Environment manifests — compose HostProfiles + agent topology per environment.

An environment manifest is a JSON file that describes which adapter hosts to
start locally AND which remote URLs the agent should connect to for a given
named environment (dev/staging/prod). Profiles stay as single-host definitions;
environments reference them by relative path.

Example ``environments/dev.json``::

    {
      "name": "dev",
      "description": "Local development",
      "hosts": [
        {"profile": "profiles/edge-host.json", "start_local": true, "optional": false}
      ],
      "agent_remotes": [
        {"url": "http://127.0.0.1:8801", "optional": false},
        {"url": "http://127.0.0.1:8802", "optional": true}
      ],
      "store": ".chp/dev-agent.sqlite"
    }

Plain string entries in ``agent_remotes`` are accepted for backward compatibility.
``${VAR}`` references in remote URLs are resolved from the environment at load time.
"""

from __future__ import annotations

import json
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from .profile import HostProfile

_ENV_RE = re.compile(r"\$\{([^}]+)\}")


def _expand(value: str) -> str:
    """Replace ${VAR} tokens with env values; leave intact if unset."""
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EnvironmentHostEntry:
    """A single host entry in an environment manifest."""

    profile: str          # relative path to HostProfile JSON (from base_dir)
    start_local: bool = True
    optional: bool = False


@dataclass
class GatewayConfig:
    """Optional gateway section — expose the full router as a CHP HTTP endpoint."""

    port: int = 8800
    bind: str = "0.0.0.0"
    host_id: str = "chp-gateway"
    # Routing strategy when several nodes own the same capability. "first"
    # (priority order, first-healthy-wins) or "round_robin" (spread load). The
    # extension seam for future capacity/locality/pinning strategies.
    selection: str = "first"
    # Gateway evidence store (spec §11): routing denials + health transitions
    # on the gateway's own chain. None → the CLI default (~/.chp/gateway-mesh.sqlite).
    store: str | None = None


@dataclass
class EnvironmentRemoteEntry:
    """A single remote agent URL entry in an environment manifest."""

    url: str
    optional: bool = False
    api_key_env: str | None = None  # name of env var holding the auth key (never stored as value)
    api_key: str | None = None      # resolved value — populated by resolve_remotes(), never in JSON
    role: str | None = None         # node role (worker/inference/nas/...) — enables affinity routing


@dataclass
class EnvironmentConfig:
    """Loaded + validated environment manifest."""

    name: str
    description: str
    hosts: list[EnvironmentHostEntry]
    agent_remotes: list[EnvironmentRemoteEntry]
    store: str
    gateway: GatewayConfig | None = None

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict) -> "EnvironmentConfig":
        if "name" not in data:
            raise ValueError("environment manifest must define 'name'")
        hosts = [
            EnvironmentHostEntry(
                profile=str(h["profile"]),
                start_local=bool(h.get("start_local", True)),
                optional=bool(h.get("optional", False)),
            )
            for h in data.get("hosts", [])
        ]
        remotes: list[EnvironmentRemoteEntry] = []
        for r in data.get("agent_remotes", []):
            if isinstance(r, str):
                remotes.append(EnvironmentRemoteEntry(url=r, optional=False))
            elif isinstance(r, dict):
                remotes.append(EnvironmentRemoteEntry(
                    url=str(r["url"]),
                    optional=bool(r.get("optional", False)),
                    api_key_env=r.get("api_key_env") or None,
                    role=r.get("role") or None,
                ))
        gateway_raw = data.get("gateway")
        gateway = (
            GatewayConfig(
                port=int(gateway_raw.get("port", 8800)),
                bind=str(gateway_raw.get("bind", "0.0.0.0")),
                host_id=str(gateway_raw.get("host_id", "chp-gateway")),
                selection=str(gateway_raw.get("selection", "first")),
                store=(str(Path(str(gateway_raw["store"])).expanduser())
                       if gateway_raw.get("store") else None),
            )
            if isinstance(gateway_raw, dict)
            else None
        )
        store_raw = str(data.get("store", f".chp/{data['name']}-agent.sqlite"))
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            hosts=hosts,
            agent_remotes=remotes,
            store=str(Path(store_raw).expanduser()),
            gateway=gateway,
        )

    @classmethod
    def load(cls, name_or_path: str, base_dir: str = ".") -> "EnvironmentConfig":
        """Load by environment name (looks in ``<base_dir>/environments/``) or by explicit path."""
        path = Path(name_or_path)
        if not path.exists():
            candidate = Path(base_dir) / "environments" / f"{name_or_path}.json"
            if candidate.exists():
                path = candidate
            else:
                raise FileNotFoundError(
                    f"Environment {name_or_path!r} not found at {path} "
                    f"or {candidate}"
                )
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict):
            raise ValueError("environment manifest must contain a JSON object")
        return cls.from_dict(raw)

    # ------------------------------------------------------------------
    # Derived views
    # ------------------------------------------------------------------

    def resolve_remotes(self) -> list[EnvironmentRemoteEntry]:
        """Return agent_remotes with ${VAR} tokens expanded and api_key_env resolved."""
        resolved = []
        for entry in self.agent_remotes:
            api_key = os.environ.get(entry.api_key_env) if entry.api_key_env else None
            resolved.append(EnvironmentRemoteEntry(
                url=_expand(entry.url),
                optional=entry.optional,
                api_key_env=entry.api_key_env,
                api_key=api_key,
                role=entry.role,
            ))
        return resolved

    def host_profiles_with_entries(self, base_dir: str = ".") -> list[tuple[HostProfile, EnvironmentHostEntry]]:
        """Load HostProfile for each start_local=True entry; skip optional missing profiles."""
        result: list[tuple[HostProfile, EnvironmentHostEntry]] = []
        for entry in self.hosts:
            if not entry.start_local:
                continue
            profile_path = Path(base_dir) / entry.profile
            try:
                result.append((HostProfile.load(profile_path), entry))
            except (OSError, ValueError) as exc:
                if entry.optional:
                    warnings.warn(
                        f"Optional host profile {entry.profile!r} skipped: {exc}",
                        stacklevel=2,
                    )
                else:
                    raise
        return result

    def host_profiles(self, base_dir: str = ".") -> list[HostProfile]:
        """Load HostProfile for each entry in hosts (start_local=True only by default)."""
        return [p for p, _ in self.host_profiles_with_entries(base_dir)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def list_environments(environments_dir: str = "environments") -> list[str]:
    """Return sorted list of environment names found in *environments_dir*."""
    d = Path(environments_dir)
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.json"))
