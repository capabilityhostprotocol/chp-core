"""Repo capabilities for the Radicle adapter."""
from __future__ import annotations

import os
import re
import tarfile
from pathlib import Path
from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
    _parse_kv,
)


class RepoOps:
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

    @capability(
        id="chp.adapters.radicle.init",
        version=_RAD_CLI_VERSION,
        description=(
            "Initialize an existing git repository as a Radicle repo (rad init) and return its durable "
            "RID. The path MUST already be a git repository. Name/description are repo metadata, not "
            "secrets; nothing beyond the returned identity is stored in evidence."
        ),
        category="developer_tooling",
        risk="high",  # creates durable p2p identity — a material, non-trivially-reversible effect
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to the git repo to initialize (defaults to cwd)"},
                "name": {"type": "string", "description": "Repository name"},
                "description": {"type": "string", "description": "Repository description"},
                "default_branch": {"type": "string", "description": "Default branch (default: main)"},
                "private": {"type": "boolean", "description": "Private visibility (default: true)"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "repo", "init", "identity"],
    )
    async def init(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        name = payload["name"]
        description = payload.get("description", "")
        default_branch = payload.get("default_branch")  # optional — omit so rad uses the repo's HEAD
        private = payload.get("private", True)
        visibility = "private" if private else "public"
        ctx.emit("radicle_request", {"operation": "init", "repo_path": repo, "name": name, "visibility": visibility})
        # --no-confirm keeps rad non-interactive (no stdin under subprocess); visibility is explicit.
        # --default-branch is only passed when the caller specifies it: forcing a branch that doesn't
        # exist in the repo (e.g. 'main' on a 'master' repo) makes rad init fail.
        args = [
            "init", repo,
            "--name", name,
            "--description", description,
            "--no-confirm",
            "--private" if private else "--public",
        ]
        if default_branch:
            args += ["--default-branch", str(default_branch)]
        try:
            raw = self._backend().run(*args)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "init", "error": str(exc)})
            raise
        m = re.search(r"rad:[A-Za-z0-9]+", raw)
        rid = m.group(0) if m else ""
        result = {"rid": rid, "name": name, "visibility": visibility, "default_branch": default_branch, "ok": bool(rid)}
        ctx.emit("radicle_response", {"operation": "init", "rid": rid, "name": name})
        return result

    @capability(
        id="chp.adapters.radicle.clone",
        version=_RAD_CLI_VERSION,
        description=(
            "Clone a Radicle repository by RID from the network (its seeds) into a destination directory "
            "and return the local checkout path. This is how a Creation is recovered from the sovereign "
            "substrate after hosted-state loss: the RID + its seeds are enough — no hosted export needed. "
            "Use --seed for a private repo whose seeds aren't in the local routing table."
        ),
        category="developer_tooling",
        risk="medium",  # fetches + writes a working copy, no destructive local effect
        input_schema={
            "type": "object",
            "properties": {
                "rid": {"type": "string", "description": "Repository ID (rad:... or rad://...) to clone"},
                "dest": {"type": "string", "description": "Target directory for the checkout"},
                "seed": {"type": "string", "description": "Node ID (NID) of a seed to clone directly from (private repos)"},
                "scope": {"type": "string", "enum": ["all", "followed"], "description": "Follow scope for the clone"},
            },
            "required": ["rid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "clone", "recover", "sovereignty"],
    )
    async def clone(self, ctx: Any, payload: dict) -> dict:
        rid = payload["rid"]
        dest = payload.get("dest")
        seed = payload.get("seed")
        scope = payload.get("scope")
        ctx.emit("radicle_request", {"operation": "clone", "rid": rid, "dest": dest})
        args = ["clone", rid]
        if dest:
            args.append(dest)
        if seed:
            args += ["--seed", seed]
        if scope:
            args += ["--scope", scope]
        # cwd is the parent the checkout lands under when no absolute dest is given; harmless otherwise.
        cwd = str(Path(dest).parent) if dest else os.getcwd()
        try:
            raw = self._backend().run(*args, cwd=cwd)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "clone", "error": str(exc)})
            raise
        # Prefer the caller's dest; else parse the checkout path rad prints ("in ./<name>").
        checkout = dest or ""
        if not checkout:
            m = re.search(r"in\s+(\S+)", raw)
            if m:
                checkout = m.group(1).rstrip(".")
        result = {"rid": rid, "dest": checkout, "ok": True}
        ctx.emit("radicle_response", {"operation": "clone", "rid": rid, "dest": checkout})
        return result

    @capability(
        id="chp.adapters.radicle.snapshot",
        version=_RAD_CLI_VERSION,
        description="Snapshot the local Radicle home (identity keys, config, storage) into a tar.gz "
                    "artifact for governed backup. Storage holds COBs (issues/patches) under "
                    "refs/namespaces — which working-tree git bundles miss — plus the seeded repos.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "dest_path": {"type": "string",
                              "description": "Absolute path to write the tar.gz snapshot to"},
                "include": {"type": "array",
                            "items": {"type": "string", "enum": ["keys", "config", "storage"]},
                            "description": "Parts of the radicle home to include (default: all three)"},
                "rad_home": {"type": "string",
                             "description": "Radicle home (default: $RAD_HOME or ~/.radicle)"},
            },
            "required": ["dest_path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "backup", "snapshot", "cobs"],
    )
    async def snapshot(self, ctx: Any, payload: dict) -> dict:
        include = payload.get("include") or ["keys", "config", "storage"]
        home = Path(payload.get("rad_home") or os.environ.get("RAD_HOME")
                    or (Path.home() / ".radicle"))
        dest = Path(payload["dest_path"])
        ctx.emit("radicle_request",
                 {"operation": "snapshot", "rad_home": str(home), "include": include})
        # selector → concrete path under the radicle home. The private key rides along as-is;
        # it is encrypted-at-rest when `rad auth` set a passphrase (aes256-ctr/bcrypt header).
        members = {"keys": home / "keys", "config": home / "config.json",
                   "storage": home / "storage"}
        try:
            if not home.is_dir():
                raise RuntimeError(f"radicle home not found: {home}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            included: list[str] = []
            tmp = dest.with_name(dest.name + ".partial")
            with tarfile.open(tmp, "w:gz") as tar:
                for sel in include:
                    src = members.get(sel)
                    if src is not None and src.exists():
                        tar.add(str(src), arcname=f"radicle/{src.name}")
                        included.append(sel)
            os.replace(tmp, dest)
        except Exception as exc:
            ctx.emit("radicle_error", {"operation": "snapshot", "error": str(exc)})
            raise
        # sha256 is computed downstream by the fabric transfer (publish_file) — the content
        # address / integrity check lives there, so the snapshot cap does no raw file reads.
        size = dest.stat().st_size
        ctx.emit("radicle_response",
                 {"operation": "snapshot", "size": size, "included": included})
        return {"path": str(dest), "size": size, "included": included}

    @capability(
        id="chp.adapters.radicle.restore",
        version=_RAD_CLI_VERSION,
        description=(
            "Restore a Radicle repo's canonical branch to an earlier revision, APPEND-ONLY: a new commit "
            "whose tree equals <revision> is created (old HEAD as parent, history preserved) and pushed. "
            "Nothing is rewritten. Returns the new revision. Mutates the canonical branch."
        ),
        category="developer_tooling",
        risk="high",  # mutates the canonical branch — a material effect
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "revision": {"type": "string", "description": "The git revision (SHA) to restore the tree to"},
                "default_branch": {"type": "string", "description": "Canonical branch (default: main)"},
                "remote": {"type": "string", "description": "Git remote (default: rad)"},
                "message": {"type": "string", "description": "Restore commit message"},
            },
            "required": ["revision"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "restore", "revision"],
    )
    async def restore(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        revision = payload["revision"]
        default_branch = payload.get("default_branch", "main")
        remote = payload.get("remote", "rad")
        message = payload.get("message", f"Restore to {revision}")
        ctx.emit("radicle_request", {"operation": "restore", "revision": revision})
        backend = self._backend()
        try:
            old_head = backend.git("rev-parse", "HEAD", cwd=repo)
            # hard-reset the tree to <revision>, then move the branch ref back to old HEAD keeping that
            # tree staged, then commit: the result is a NEW commit whose tree == <revision> with old HEAD
            # as parent — a full-tree restore that preserves history (append-only). No force push.
            backend.git("reset", "--hard", revision, cwd=repo)
            backend.git("reset", "--soft", old_head, cwd=repo)
            backend.git("-c", "user.name=Sprig Restore", "-c", "user.email=restore@sprig.local", "commit", "-m", message, cwd=repo)
            new_rev = backend.git("rev-parse", "HEAD", cwd=repo)
            backend.git_push(remote, default_branch, cwd=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "restore", "error": str(exc)})
            raise
        result = {"revision": new_rev, "restored_from": revision, "ok": bool(new_rev)}
        ctx.emit("radicle_response", {"operation": "restore", "revision": new_rev, "restored_from": revision})
        return result
