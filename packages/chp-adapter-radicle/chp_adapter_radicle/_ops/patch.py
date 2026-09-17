"""Patch capabilities for the Radicle adapter."""
from __future__ import annotations

import re
from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
    _parse_box_table,
    _state_flag,
)


class PatchOps:
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

    @capability(
        id="chp.adapters.radicle.patch_open",
        version=_RAD_CLI_VERSION,
        description=(
            "Open a new Radicle patch from the current HEAD by pushing to the magic refs/patches ref "
            "(rad has no 'patch open' subcommand). The patch title/body come from the HEAD commit; "
            "returns the opened patch id."
        ),
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "title": {"type": "string", "description": "Patch title (informational; the patch takes the HEAD commit message)"},
                "remote": {"type": "string", "description": "Git remote (default: rad)"},
            },
            "required": ["title"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "patch", "open"],
    )
    async def patch_open(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        title = payload["title"]
        remote = payload.get("remote", "rad")
        ctx.emit("radicle_request", {"operation": "patch_open", "title": title})
        # rad 1.9.1 has no `patch open`; pushing HEAD to the magic refs/patches ref opens a patch.
        try:
            raw = self._backend().git("push", remote, "HEAD:refs/patches", cwd=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "patch_open", "error": str(exc)})
            raise
        m = re.search(r"Patch\s+([0-9a-f]{7,40})\s+opened", raw, re.IGNORECASE)
        patch_id = m.group(1) if m else ""
        result = {"patch_id": patch_id, "title": title, "ok": bool(patch_id)}
        ctx.emit("radicle_response", {"operation": "patch_open", "patch_id": patch_id})
        return result

    @capability(
        id="chp.adapters.radicle.patch_merge",
        version=_RAD_CLI_VERSION,
        description=(
            "Merge (land) an open Radicle patch into the canonical branch. rad has no 'patch merge' "
            "verb; the delegate flow is: checkout the patch head, merge it into the default branch, and "
            "push — pushing the canonical branch is what marks the patch merged. MUTATES the canonical "
            "branch; fails cleanly (no push) on a non-fast-forward/conflict."
        ),
        category="developer_tooling",
        risk="high",  # mutates the canonical branch — a material, hard-to-reverse effect
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "patch_id": {"type": "string", "description": "ID of the patch to merge"},
                "default_branch": {"type": "string", "description": "Canonical branch to merge into (default: main)"},
                "remote": {"type": "string", "description": "Git remote (default: rad)"},
            },
            "required": ["patch_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "patch", "merge", "land"],
    )
    async def patch_merge(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        patch_id = payload["patch_id"]
        default_branch = payload.get("default_branch", "main")
        remote = payload.get("remote", "rad")
        tmp_branch = f"patch-{patch_id[:12]}"
        ctx.emit("radicle_request", {"operation": "patch_merge", "patch_id": patch_id, "default_branch": default_branch})
        backend = self._backend()
        try:
            # 1. Fetch the patch head onto a local branch (rad patch checkout).
            backend.run("patch", "checkout", patch_id, "--name", tmp_branch, cwd=repo)
            # 2. Merge it into the canonical branch — fast-forward only, so a divergent branch fails
            #    cleanly here (before any push) rather than creating a merge commit implicitly.
            backend.git("checkout", default_branch, cwd=repo)
            backend.git("merge", "--ff-only", tmp_branch, cwd=repo)
            # 3. Push the canonical branch — Radicle marks the patch merged and advances the ref.
            raw = backend.git_push(remote, default_branch, cwd=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "patch_merge", "error": str(exc)})
            raise
        # Real 1.9.1 push output: "✓ Patch <hash> merged" + "Canonical reference ... updated to target commit <sha>".
        merged = bool(re.search(r"Patch\s+[0-9a-f]{7,40}\s+merged", raw, re.IGNORECASE)) or "merged" in raw.lower()
        commit_match = re.search(r"updated to target commit\s+([0-9a-f]{7,40})", raw)
        canonical_commit = commit_match.group(1) if commit_match else ""
        result = {"patch_id": patch_id, "merged": merged, "default_branch": default_branch, "canonical_commit": canonical_commit}
        ctx.emit("radicle_response", {"operation": "patch_merge", "patch_id": patch_id, "merged": merged})
        return result

    @capability(
        id="chp.adapters.radicle.patch_show",
        version=_RAD_CLI_VERSION,
        description=(
            "Show a patch's CANONICAL diff (rad patch diff <id>) — the actual git diff of the change, so a "
            "reviewer accepts the REAL change, not a proposing agent's self-reported summary ('intelligence "
            "is not authority'). Returns the raw unified diff + the changed file paths. The diff is in the "
            "RETURN value for the caller to render; it is NOT emitted to evidence (only patch id + file "
            "count), matching patch_list's discipline. Read-only."
        ),
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "patch_id": {"type": "string", "description": "ID of the patch to show the diff of"},
            },
            "required": ["patch_id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "patch", "diff", "review"],
    )
    async def patch_show(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        patch_id = payload["patch_id"]
        ctx.emit("radicle_request", {"operation": "patch_show", "patch_id": patch_id})
        try:
            diff = self._rad("patch", "diff", patch_id, repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "patch_show", "error": str(exc)})
            raise
        # Changed file paths from the unified diff's "+++ b/<path>" lines (never in evidence — metadata only).
        files = sorted({m.group(1) for m in re.finditer(r"^\+\+\+ b/(.+)$", diff, re.MULTILINE)})
        result = {"patch_id": patch_id, "diff": diff, "files": files, "ok": True}
        ctx.emit("radicle_response", {"operation": "patch_show", "patch_id": patch_id, "file_count": len(files)})
        return result
