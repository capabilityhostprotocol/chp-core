"""RadicleAdapter — Radicle p2p code forge. Capabilities are organized into discrete domain
mixins under ``_ops/`` (repo, patch, issue, node, seed, identity) for extensibility; this module
composes them and provides the shared backend/repo/rad helpers. Cap ids are unchanged."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter

from .backend import FakeRadicleBackend, RadicleBackend, SubprocessRadicleBackend
from ._ops.identity import IdentityOps
from ._ops.issue import IssueOps
from ._ops.node import NodeOps
from ._ops.patch import PatchOps
from ._ops.repo import RepoOps
from ._ops.seed import SeedOps

__all__ = ["RadicleAdapter", "RadicleConfig", "RadicleBackend", "SubprocessRadicleBackend", "FakeRadicleBackend"]


@dataclass
class RadicleConfig:
    """Config for RadicleAdapter."""

    default_repo_path: str | None = None
    backend: Any = None  # RadicleBackend implementation

    def _effective_repo_path(self) -> str:
        return self.default_repo_path or os.getcwd()

    def _effective_backend(self) -> RadicleBackend:
        return self.backend if self.backend is not None else SubprocessRadicleBackend()


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class RadicleAdapter(BaseAdapter, RepoOps, PatchOps, IssueOps, NodeOps, SeedOps, IdentityOps):
    """Radicle peer-to-peer code forge — sync, patch, issue, repo identity."""

    adapter_id = "chp.adapters.radicle"
    adapter_name = "Radicle"
    adapter_description = "Radicle p2p code forge — sync, patch, issue, repo identity"
    adapter_category = "developer_tooling"
    adapter_tags = ["radicle", "vcs", "p2p", "patch", "issue", "forge"]

    def __init__(self, config: RadicleConfig | None = None) -> None:
        self._config = config or RadicleConfig()

    def _backend(self) -> RadicleBackend:
        return self._config._effective_backend()

    def _repo(self, payload: dict) -> str:
        return payload.get("repo_path") or self._config._effective_repo_path()

    def _rad(self, *args: str, repo: str) -> str:
        return self._backend().run(*args, cwd=repo)
