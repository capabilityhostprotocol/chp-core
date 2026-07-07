"""RadicleAdapter — Radicle p2p code forge operations as CHP capabilities.

Tested against rad CLI 1.6.1. Capability versions are pinned to that CLI version
so future upgrades are immediately visible as version mismatches.

NOTE: patch_open is not supported in rad 1.6.1 — use the push capability instead.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

from .backend import FakeRadicleBackend, RadicleBackend, SubprocessRadicleBackend

_EMITS = ["radicle_request", "radicle_response", "radicle_error"]
_RAD_CLI_VERSION = "1.6.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_kv(output: str) -> dict[str, str]:
    """Parse ``Key   value`` lines (as emitted by ``rad inspect``, ``rad self``)."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower().rstrip(":")] = parts[1].strip()
    return result


def _parse_box_kv(output: str) -> dict[str, str]:
    """Parse the box-drawing table emitted by ``rad issue show``.

    Each content row looks like:  │ Key   value text   │
    Returns a dict with lowercase keys.
    """
    result: dict[str, str] = {}
    for line in output.splitlines():
        # Strip box chars and leading/trailing whitespace
        inner = line.strip().lstrip("│╭╰├╯").rstrip("│╮╯┤").strip()
        if not inner or inner.startswith("─") or inner.startswith("┤"):
            continue
        parts = inner.split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower().rstrip(":")
            # Only capture known header keys; skip body lines
            if key in ("title", "issue", "author", "labels", "status", "assignees"):
                result[key] = parts[1].strip()
    return result


def _parse_box_table(output: str) -> list[dict[str, str]]:
    """Parse the box-drawing table emitted by ``rad issue list`` / ``rad patch list``.

    Data rows have the form:  │ ●   <id>   <rest...>   │
    Returns list of dicts with at minimum ``id`` and ``title``.
    """
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        inner = line.strip()
        if not inner.startswith("│"):
            continue
        inner = inner.lstrip("│").rstrip("│").strip()
        # Skip header/separator rows (no ● marker or starts with ID header)
        if not inner.startswith("●"):
            continue
        inner = inner.lstrip("●").strip()
        # Split into fields by 2+ spaces
        fields = re.split(r"\s{2,}", inner)
        if len(fields) >= 2 and re.match(r"^[0-9a-f]{7,40}$", fields[0]):
            row: dict[str, str] = {"id": fields[0], "title": fields[1]}
            # fields: id, title, author, (you), labels, opened
            # Labels have no spaces; timestamps do ("17 hours ago")
            if len(fields) >= 5 and fields[4] and " " not in fields[4]:
                row["labels"] = fields[4]
            rows.append(row)
    return rows


def _parse_issue_table(output: str) -> list[dict]:
    """Parse ``rad issue list`` — fixed-width columns ID/Title/Author/Labels/Assignees/Opened.

    Slices each data row by the header column positions (robust to content width) and returns
    ``{id, title, labels: [...]}``. The Labels column is comma-separated.
    """
    lines = output.splitlines()
    header = next((ln for ln in lines if "ID" in ln and "Title" in ln and "Labels" in ln), None)
    if header is None:
        return []
    cols = ["ID", "Title", "Author", "Labels", "Assignees", "Opened"]
    pos = {c: header.find(c) for c in cols if header.find(c) >= 0}
    present = [c for c in cols if c in pos]
    rows: list[dict] = []
    for ln in lines:
        if "●" not in ln or not ln.lstrip().startswith("│"):
            continue
        cell: dict[str, str] = {}
        for i, c in enumerate(present):
            start = pos[c]
            end = pos[present[i + 1]] if i + 1 < len(present) else len(ln)
            cell[c.lower()] = ln[start:end].strip().rstrip("│").strip()
        iid = cell.get("id", "")
        if not re.match(r"^[0-9a-f]{7,40}$", iid):
            continue
        labels = [t.strip() for t in cell.get("labels", "").split(",") if t.strip()]
        rows.append({"id": iid, "title": cell.get("title", ""), "labels": labels})
    return rows


def _state_flag(state: str | None, valid: tuple[str, ...]) -> list[str]:
    """Convert a state string to the appropriate ``--<state>`` rad CLI flag.

    If *state* is None or not in *valid*, returns ``[]`` (CLI default applies).
    """
    if state and state in valid:
        return [f"--{state}"]
    return []


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

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

class RadicleAdapter(BaseAdapter):
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

    # ------------------------------------------------------------------
    # repo_info
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.repo_info",
        version=_RAD_CLI_VERSION,
        description="Radicle repository identity: RID, name, description, visibility, delegate count.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to the repo (defaults to cwd)"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "repo", "inspect"],
    )
    async def repo_info(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("radicle_request", {"operation": "repo_info", "repo_path": repo})
        try:
            raw = self._rad("inspect", repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "repo_info", "error": str(exc)})
            raise
        kv = _parse_kv(raw)
        # First non-empty line is often "rad:RID"
        rid = ""
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("rad:"):
                rid = line
                break
        result = {
            "rid": rid,
            "name": kv.get("name", ""),
            "description": kv.get("description", ""),
            "visibility": kv.get("visibility", ""),
            "delegate_count": int(re.search(r"\((\d+)\)", kv.get("delegates", "0")).group(1))
            if re.search(r"\((\d+)\)", kv.get("delegates", ""))
            else 0,
        }
        ctx.emit("radicle_response", {"operation": "repo_info", "rid": result["rid"], "name": result["name"]})
        return result

    # ------------------------------------------------------------------
    # list_repos
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.list_repos",
        version=_RAD_CLI_VERSION,
        description="List all locally tracked Radicle repositories (names + RIDs).",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "repos", "list"],
    )
    async def list_repos(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "list_repos"})
        try:
            raw = self._backend().run("ls")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "list_repos", "error": str(exc)})
            raise
        repos: list[dict] = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                rid, name = parts[0], parts[1]
                visibility = parts[2] if len(parts) > 2 else ""
                repos.append({"rid": rid, "name": name, "visibility": visibility})
        ctx.emit("radicle_response", {"operation": "list_repos", "count": len(repos)})
        return {"repos": repos, "count": len(repos)}

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.identity",
        version=_RAD_CLI_VERSION,
        description="Local Radicle identity: DID public key only. Private key / NID never returned.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "identity", "did"],
    )
    async def identity(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "identity"})
        try:
            raw = self._backend().run("self")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "identity", "error": str(exc)})
            raise
        kv = _parse_kv(raw)
        # Expose DID only — never the NID (node key) or any private material
        did = kv.get("did", "")
        result = {"did": did}
        ctx.emit("radicle_response", {"operation": "identity"})
        # NID is intentionally not returned or emitted
        return result

    # ------------------------------------------------------------------
    # node_status
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.node_status",
        version=_RAD_CLI_VERSION,
        description="Radicle node status: running/stopped, connected peer count.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "node", "status"],
    )
    async def node_status(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "node_status"})
        try:
            raw = self._backend().run("node", "status")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "node_status", "error": str(exc)})
            raise
        not_running = "not running" in raw.lower() or "stopped" in raw.lower()
        running = (("running" in raw.lower() or "started" in raw.lower()) and not not_running)
        peer_match = re.search(r"connected[:\s]+(\d+)", raw, re.IGNORECASE)
        peers = int(peer_match.group(1)) if peer_match else 0
        result = {"running": running, "peers": peers, "raw_status": raw[:120]}
        ctx.emit("radicle_response", {"operation": "node_status", "running": running, "peers": peers})
        return result

    # ------------------------------------------------------------------
    # sync
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.sync",
        version=_RAD_CLI_VERSION,
        description="Sync a Radicle repo to the network (push local state to seeds).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "sync", "network"],
    )
    async def sync(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("radicle_request", {"operation": "sync", "repo_path": repo})
        try:
            raw = self._rad("sync", repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "sync", "error": str(exc)})
            raise
        ok = "error" not in raw.lower() and "✗" not in raw
        result = {"ok": ok, "message": raw[:200]}
        ctx.emit("radicle_response", {"operation": "sync", "ok": ok})
        return result

    # ------------------------------------------------------------------
    # seed_policies / seed / unseed (replication policy)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.seed_policies",
        version=_RAD_CLI_VERSION,
        description="List this node's seeding policies (which repos it replicates + scope).",
        category="developer_tooling",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=_EMITS,
        tags=["radicle", "seed", "policy", "network"],
    )
    async def seed_policies(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "seed_policies"})
        try:
            raw = self._backend().run("seed")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "seed_policies", "error": str(exc)})
            raise
        # `rad seed` rows have no ● marker; columns: Repository(rid)  Name  Policy  Scope.
        policies: list[dict] = []
        for line in raw.splitlines():
            inner = line.strip()
            if not inner.startswith("│"):
                continue
            inner = inner.strip("│").strip()
            fields = re.split(r"\s{2,}", inner)
            if len(fields) >= 4 and fields[0].startswith("rad:"):
                policies.append({"rid": fields[0], "name": fields[1],
                                 "policy": fields[2], "scope": fields[3]})
        ctx.emit("radicle_response", {"operation": "seed_policies", "count": len(policies)})
        return {"policies": policies, "count": len(policies)}

    @capability(
        id="chp.adapters.radicle.seed",
        version=_RAD_CLI_VERSION,
        description="Seed a repo on this node (create/update its replication policy). Scope 'followed' "
                    "(delegates + explicitly-followed peers) or 'all' (every remote).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "rid": {"type": "string", "description": "Repository ID (rad:...)"},
                "scope": {"type": "string", "enum": ["followed", "all"],
                          "description": "Replication scope (default: followed)"},
            },
            "required": ["rid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "seed", "network", "replication"],
    )
    async def seed(self, ctx: Any, payload: dict) -> dict:
        rid = str(payload["rid"])
        scope = payload.get("scope", "followed")
        ctx.emit("radicle_request", {"operation": "seed", "rid": rid, "scope": scope})
        try:
            raw = self._backend().run("seed", rid, "--scope", scope)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "seed", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "seed", "rid": rid, "ok": ok})
        return {"rid": rid, "scope": scope, "ok": ok, "message": raw[:200]}

    @capability(
        id="chp.adapters.radicle.unseed",
        version=_RAD_CLI_VERSION,
        description="Remove this node's seeding policy for a repo (stop replicating it).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {"rid": {"type": "string", "description": "Repository ID (rad:...)"}},
            "required": ["rid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "seed", "network"],
    )
    async def unseed(self, ctx: Any, payload: dict) -> dict:
        rid = str(payload["rid"])
        ctx.emit("radicle_request", {"operation": "unseed", "rid": rid})
        try:
            raw = self._backend().run("unseed", rid)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "unseed", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "unseed", "rid": rid, "ok": ok})
        return {"rid": rid, "ok": ok, "message": raw[:200]}

    # ------------------------------------------------------------------
    # follow / node_connect (peer replication)
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.follow",
        version=_RAD_CLI_VERSION,
        description="Follow a peer node (replicate its refs for 'followed'-scope repos).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "nid": {"type": "string", "description": "Node ID (z6Mk...)"},
                "alias": {"type": "string", "description": "Optional local alias for the peer"},
            },
            "required": ["nid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "follow", "peer", "network"],
    )
    async def follow(self, ctx: Any, payload: dict) -> dict:
        nid = str(payload["nid"])
        alias = payload.get("alias")
        args = ["follow", nid] + (["--alias", str(alias)] if alias else [])
        ctx.emit("radicle_request", {"operation": "follow", "nid": nid})
        try:
            raw = self._backend().run(*args)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "follow", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "follow", "nid": nid, "ok": ok})
        return {"nid": nid, "ok": ok, "message": raw[:200]}

    @capability(
        id="chp.adapters.radicle.node_connect",
        version=_RAD_CLI_VERSION,
        description="Instruct the node to connect to a peer at nid@host:port (establishes replication link).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "nid": {"type": "string", "description": "Peer Node ID (z6Mk...)"},
                "address": {"type": "string", "description": "Peer address host:port (e.g. 100.x.y.z:8776)"},
            },
            "required": ["nid", "address"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "node", "connect", "peer"],
    )
    async def node_connect(self, ctx: Any, payload: dict) -> dict:
        nid = str(payload["nid"])
        address = str(payload["address"])
        ctx.emit("radicle_request", {"operation": "node_connect", "nid": nid})
        try:
            raw = self._backend().run("node", "connect", f"{nid}@{address}")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "node_connect", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "node_connect", "nid": nid, "ok": ok})
        return {"nid": nid, "address": address, "ok": ok, "message": raw[:200]}

    # ------------------------------------------------------------------
    # push
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.push",
        version=_RAD_CLI_VERSION,
        description="Push a branch to the Radicle remote (git push rad <branch>).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "branch": {"type": "string", "description": "Branch name to push"},
                "remote": {"type": "string", "description": "Git remote name (default: rad)"},
            },
            "required": ["branch"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "push", "branch"],
    )
    async def push(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        branch = payload["branch"]
        remote = payload.get("remote", "rad")
        ctx.emit("radicle_request", {"operation": "push", "branch": branch, "remote": remote})
        try:
            raw = self._backend().git_push(remote, branch, cwd=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "push", "error": str(exc)})
            raise
        # Extract patch ID if Radicle updated a patch (e.g. "✓ Patch abc1234 updated")
        patch_match = re.search(r"Patch\s+([0-9a-f]{7,40})", raw, re.IGNORECASE)
        patch_id = patch_match.group(1) if patch_match else ""
        result = {"branch": branch, "remote": remote, "patch_id": patch_id, "ok": True}
        ctx.emit("radicle_response", {"operation": "push", "branch": branch, "patch_id": patch_id})
        return result

    # ------------------------------------------------------------------
    # patch_list
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.patch_list",
        version=_RAD_CLI_VERSION,
        description="List Radicle patches: IDs, titles, states. Patch body and diff never in evidence.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "state": {
                    "type": "string",
                    "enum": ["open", "merged", "archived", "draft", "all"],
                    "description": "Filter by patch state (omit for open patches only). Use 'all' for every state.",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "patch", "list"],
    )
    async def patch_list(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        state_filter = payload.get("state")
        ctx.emit("radicle_request", {"operation": "patch_list", "state": state_filter})
        try:
            # rad 1.6.1: --open | --merged | --archived | --draft | --all (no --state flag)
            args = ["patch", "list"] + _state_flag(state_filter, ("open", "merged", "archived", "draft", "all"))
            raw = self._rad(*args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "patch_list", "error": str(exc)})
            raise
        patches = _parse_box_table(raw)
        ctx.emit("radicle_response", {"operation": "patch_list", "count": len(patches)})
        return {"patches": patches, "count": len(patches)}

    # ------------------------------------------------------------------
    # patch_open
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.patch_open",
        version=_RAD_CLI_VERSION,
        description="Open a new Radicle patch for the current branch. Patch body never in evidence.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "title": {"type": "string", "description": "Patch title"},
                "base": {"type": "string", "description": "Base branch (default: master)"},
                "body": {"type": "string", "description": "Patch description (never stored in evidence)"},
            },
            "required": ["title"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "patch", "open"],
    )
    async def patch_open(self, ctx: Any, payload: dict) -> dict:
        """Not supported in rad 1.6.1.

        In rad 1.6.1 patches are created automatically when you push a branch
        to the rad remote. Use the ``push`` capability instead.
        """
        ctx.emit("radicle_error", {
            "operation": "patch_open",
            "error": "rad 1.6.1 has no 'rad patch open' command. Push the branch via the 'push' capability to create a patch.",
        })
        raise RuntimeError(
            "patch_open is not supported in rad 1.6.1. "
            "Use 'chp.adapters.radicle.push' to push a branch and create a patch automatically."
        )

    # ------------------------------------------------------------------
    # issue_list
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_list",
        version=_RAD_CLI_VERSION,
        description="List Radicle issues: IDs, titles, labels. Issue body never in evidence.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "solved", "all"],
                    "description": "Filter by state (default: open). rad 1.6.1 flags: --open|--closed|--solved|--all",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "list"],
    )
    async def issue_list(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        state_filter = payload.get("state", "open")
        ctx.emit("radicle_request", {"operation": "issue_list", "state": state_filter})
        try:
            # rad 1.6.1: --open | --closed | --solved | --all (no --state flag)
            args = ["issue", "list"] + _state_flag(state_filter, ("open", "closed", "solved", "all"))
            raw = self._rad(*args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_list", "error": str(exc)})
            raise
        issues = _parse_issue_table(raw)
        ctx.emit("radicle_response", {"operation": "issue_list", "count": len(issues)})
        return {"issues": issues, "count": len(issues)}

    # ------------------------------------------------------------------
    # issue_open
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_open",
        version=_RAD_CLI_VERSION,
        description="Open a new Radicle issue. Issue body never in evidence.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "title": {"type": "string", "description": "Issue title"},
                "body": {"type": "string", "description": "Issue body (never stored in evidence)"},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels to attach",
                },
            },
            "required": ["title"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "open"],
    )
    async def issue_open(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        title = payload["title"]
        # body and labels intentionally not emitted in evidence
        ctx.emit("radicle_request", {"operation": "issue_open", "title": title})
        try:
            # Always pass --description so `rad issue open` is non-interactive (no $EDITOR).
            # (Older code used --no-edit, which current rad rejects.)
            args = ["issue", "open", "--title", title, "--description", payload.get("body") or title]
            for lbl in (payload.get("labels") or []):
                args += ["--labels", lbl]
            raw = self._rad(*args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_open", "error": str(exc)})
            raise
        issue_match = re.search(r"[0-9a-f]{7,40}", raw)
        issue_id = issue_match.group(0) if issue_match else ""
        ctx.emit("radicle_response", {"operation": "issue_open", "issue_id": issue_id, "title": title})
        return {"issue_id": issue_id, "title": title}

    # ------------------------------------------------------------------
    # issue_show
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_show",
        version=_RAD_CLI_VERSION,
        description="Show a Radicle issue: title, state, comment count. Body never in evidence.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "issue_id": {"type": "string", "description": "Issue ID (short hash)"},
            },
            "required": ["issue_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "show"],
    )
    async def issue_show(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        issue_id = payload["issue_id"]
        ctx.emit("radicle_request", {"operation": "issue_show", "issue_id": issue_id})
        try:
            raw = self._rad("issue", "show", issue_id, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_show", "error": str(exc)})
            raise
        # rad 1.6.1 emits a box-drawing table, not key-value lines
        kv = _parse_box_kv(raw)
        result = {
            "issue_id": issue_id,
            "title": kv.get("title", ""),
            "state": kv.get("status", ""),
            "labels": kv.get("labels", ""),
        }
        # body not included in result or evidence
        ctx.emit("radicle_response", {"operation": "issue_show", "issue_id": issue_id, "state": result["state"]})
        return result

    # ------------------------------------------------------------------
    # issue_comment
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_comment",
        version=_RAD_CLI_VERSION,
        description="Post a comment on a Radicle issue. Comment text never in evidence.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "issue_id": {"type": "string", "description": "Issue ID"},
                "message": {"type": "string", "description": "Comment text (never stored in evidence)"},
            },
            "required": ["issue_id", "message"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "comment"],
    )
    async def issue_comment(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        issue_id = payload["issue_id"]
        message = payload["message"]
        # message intentionally not emitted in evidence
        ctx.emit("radicle_request", {"operation": "issue_comment", "issue_id": issue_id})
        try:
            self._rad("issue", "comment", issue_id, "-m", message, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_comment", "error": str(exc)})
            raise
        ctx.emit("radicle_response", {"operation": "issue_comment", "issue_id": issue_id})
        return {"issue_id": issue_id, "posted": True}

    # ------------------------------------------------------------------
    # issue_close
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_close",
        version=_RAD_CLI_VERSION,
        description="Close a Radicle issue by ID.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "issue_id": {"type": "string", "description": "Issue ID to close"},
            },
            "required": ["issue_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "close"],
    )
    async def issue_close(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        issue_id = payload["issue_id"]
        ctx.emit("radicle_request", {"operation": "issue_close", "issue_id": issue_id})
        try:
            # rad 1.6.1: no 'rad issue close'; use 'rad issue state --closed <id>'
            self._rad("issue", "state", "--closed", issue_id, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_close", "error": str(exc)})
            raise
        ctx.emit("radicle_response", {"operation": "issue_close", "issue_id": issue_id})
        return {"issue_id": issue_id, "closed": True}

    # ------------------------------------------------------------------
    # issue_label — the Intake (approve) gesture: add/remove labels
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.radicle.issue_label",
        version=_RAD_CLI_VERSION,
        description="Add and/or remove labels on an existing issue (approve = add 'approved-for-dev').",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "issue_id": {"type": "string"},
                "add": {"type": "array", "items": {"type": "string"}, "description": "Labels to add"},
                "remove": {"type": "array", "items": {"type": "string"}, "description": "Labels to remove"},
            },
            "required": ["issue_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "issue", "label"],
    )
    async def issue_label(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        issue_id = payload["issue_id"]
        add = [str(x) for x in (payload.get("add") or [])]
        remove = [str(x) for x in (payload.get("remove") or [])]
        ctx.emit("radicle_request", {"operation": "issue_label", "issue_id": issue_id, "add": add, "remove": remove})
        if not add and not remove:
            ctx.emit("radicle_error", {"operation": "issue_label", "error": "no labels to add or remove"})
            raise RuntimeError("issue_label requires at least one of add/remove")
        args = ["issue", "label", issue_id]
        for label in add:
            args += ["--add", label]
        for label in remove:
            args += ["--delete", label]
        try:
            self._rad(*args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "issue_label", "error": str(exc)})
            raise
        ctx.emit("radicle_response", {"operation": "issue_label", "issue_id": issue_id})
        return {"issue_id": issue_id, "added": add, "removed": remove, "ok": True}
