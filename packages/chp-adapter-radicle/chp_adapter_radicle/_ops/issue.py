"""Issue capabilities for the Radicle adapter."""
from __future__ import annotations

import re
from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
    _parse_box_kv,
    _parse_issue_table,
    _state_flag,
)


class IssueOps:
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
        # rad 1.9.1 emits a box-drawing table, not key-value lines
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
