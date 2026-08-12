"""GitAdapter — local Git repository inspection and operations as CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Diff content (patch text) — NEVER in evidence; only ``files_changed``,
  ``insertions``, ``deletions`` counts.
* File content — NEVER in evidence.
* Full commit message bodies beyond the subject line — NOT in evidence; only
  first 80 chars of each commit subject.
* Unstaged/staged file content — NEVER in evidence; only file path lists.

Capabilities:

* ``status``          — working tree status: branch, staged/unstaged/untracked counts
* ``inspect_repo``    — branch, HEAD SHA, remotes, contributor count
* ``log``             — recent commits list (sha7, author, subject, date)
* ``diff_summary``    — files changed, insertions, deletions (NO patch text)
* ``precommit_check`` — staged file list + unstaged changes count
* ``checkout_branch`` — create or switch to a branch
* ``commit``          — stage specified files and commit with a message
* ``push`` / ``pull`` / ``merge`` — remote + integration operations
* ``discover_repos``  — bounded walk for git repositories under a root
* ``bundle``          — single-file snapshot (``git bundle --all``), verified + hashed
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from chp_core import BaseAdapter, capability

_EMITS = ["git_request", "git_response", "git_error"]

_git_ensured = False


def ensure_git_installed() -> None:
    """Ensure the ``git`` binary is available; install it best-effort if missing.

    Mesh nodes don't always ship git (a minimal NUC image, a fresh container), which
    otherwise breaks every git capability with 'command not found'. Check once; if absent,
    install via the platform package manager (with ``sudo -n`` when not root). Raise a clear
    error if it genuinely can't be installed, rather than failing opaquely later."""
    global _git_ensured
    if _git_ensured or shutil.which("git"):
        _git_ensured = True
        return
    is_root = getattr(os, "geteuid", lambda: 1)() == 0
    sudo = [] if is_root else (["sudo", "-n"] if shutil.which("sudo") else None)
    if sudo is None:
        raise RuntimeError("git is not installed and cannot be auto-installed (no root and no sudo)")
    # (manager, install steps). apt needs an index refresh first; brew refuses to run as root.
    managers = [
        ("apt-get", [["apt-get", "update"], ["apt-get", "install", "-y", "git"]]),
        ("dnf", [["dnf", "install", "-y", "git"]]),
        ("yum", [["yum", "install", "-y", "git"]]),
        ("apk", [["apk", "add", "--no-cache", "git"]]),
        ("brew", [["brew", "install", "git"]]),
    ]
    for mgr, steps in managers:
        if not shutil.which(mgr):
            continue
        prefix = [] if mgr == "brew" else sudo
        try:
            for step in steps:
                subprocess.run(prefix + step, check=True, capture_output=True, timeout=300)
        except Exception:  # noqa: BLE001 — try the next available manager
            continue
        if shutil.which("git"):
            _git_ensured = True
            return
    raise RuntimeError("git is not installed and auto-install via the platform package manager failed")


# ---------------------------------------------------------------------------
# Injectable backend
# ---------------------------------------------------------------------------

@runtime_checkable
class GitBackend(Protocol):
    """Minimal interface for running git sub-commands."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        """Run ``git <args>`` and return stdout. Raises RuntimeError on non-zero exit."""
        ...


class SubprocessGitBackend:
    """Production backend: delegates to the ``git`` binary via subprocess."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        ensure_git_installed()
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"git {args[0]} failed")
        return result.stdout.strip()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class GitConfig:
    """Config for GitAdapter.

    ``default_repo_path`` can be overridden per-call via the ``repo_path``
    payload field.  ``backend`` accepts a test double for unit isolation.
    ``max_log_entries`` caps how many commits ``log`` returns.
    """

    default_repo_path: str | None = None
    max_log_entries: int = 50
    backend: Any = None  # GitBackend implementation

    def _effective_repo_path(self) -> str:
        return self.default_repo_path or os.getcwd()

    def _effective_backend(self) -> GitBackend:
        return self.backend if self.backend is not None else SubprocessGitBackend()


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class GitAdapter(BaseAdapter):
    """Git repository inspection and lightweight write operations."""

    adapter_id = "chp.adapters.git"
    adapter_name = "Git"
    adapter_description = "Local Git repository inspection and operations"
    adapter_category = "developer_tooling"
    adapter_tags = ["git", "vcs", "repository", "diff", "commit"]

    def __init__(self, config: GitConfig | None = None) -> None:
        self._config = config or GitConfig()

    def _backend(self) -> GitBackend:
        return self._config._effective_backend()

    def _repo(self, payload: dict) -> str:
        return payload.get("repo_path") or self._config._effective_repo_path()

    def _git(self, *args: str, repo: str) -> str:
        return self._backend().run(*args, cwd=repo)

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.status",
        version="0.1.0",
        description="Working tree status: branch name, staged/unstaged/untracked file counts.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Absolute path to the git repo (defaults to config)"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "status"],
    )
    async def status(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("git_request", {"operation": "status", "repo_path": repo})
        try:
            branch = self._git("rev-parse", "--abbrev-ref", "HEAD", repo=repo)
            porcelain = self._git("status", "--porcelain", repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "status", "error": str(exc)})
            raise

        staged = unstaged = untracked = 0
        for line in porcelain.splitlines():
            if len(line) < 2:
                continue
            x, y = line[0], line[1]
            if x == "?" and y == "?":
                untracked += 1
            elif x != " " and x != "?":
                staged += 1
            if y not in (" ", "?"):
                unstaged += 1

        result = {
            "branch": branch,
            "staged": staged,
            "unstaged": unstaged,
            "untracked": untracked,
            "clean": staged == 0 and unstaged == 0 and untracked == 0,
        }
        ctx.emit("git_response", {"operation": "status", **result})
        return result

    # ------------------------------------------------------------------
    # inspect_repo
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.inspect_repo",
        version="0.1.0",
        description="Repository overview: branch, HEAD SHA, remotes, commit count.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "repo", "inspect"],
    )
    async def inspect_repo(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("git_request", {"operation": "inspect_repo", "repo_path": repo})
        try:
            branch = self._git("rev-parse", "--abbrev-ref", "HEAD", repo=repo)
            head_sha = self._git("rev-parse", "HEAD", repo=repo)
            remotes_raw = self._git("remote", "-v", repo=repo)
            commit_count_raw = self._git("rev-list", "--count", "HEAD", repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "inspect_repo", "error": str(exc)})
            raise

        remotes: list[str] = []
        seen: set[str] = set()
        for line in remotes_raw.splitlines():
            parts = line.split()
            if parts and parts[0] not in seen:
                remotes.append(parts[0])
                seen.add(parts[0])

        result = {
            "branch": branch,
            "head_sha": head_sha[:40],
            "head_sha7": head_sha[:7],
            "remotes": remotes,
            "commit_count": int(commit_count_raw) if commit_count_raw.isdigit() else 0,
        }
        ctx.emit("git_response", {"operation": "inspect_repo", "branch": result["branch"], "commit_count": result["commit_count"]})
        return result

    # ------------------------------------------------------------------
    # log
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.log",
        version="0.2.0",
        description="Recent commit list: sha7, author name, subject (truncated), ISO date, and "
                    "optionally the full commit body.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "branch": {"type": "string"},
                "include_body": {
                    "type": "boolean",
                    "description": "Include each commit's full message body. Callers that link "
                                   "commits back to their own records need it: the trailers that "
                                   "name an issue or record live in the body, not the subject.",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "log", "commits"],
    )
    async def log(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        limit = min(int(payload.get("limit") or 20), self._config.max_log_entries)
        branch = payload.get("branch") or "HEAD"
        include_body = bool(payload.get("include_body"))
        ctx.emit("git_request", {"operation": "log", "repo_path": repo, "limit": limit,
                                 "branch": branch})
        # Fields are US-separated; RECORDS are NUL-separated. A body is multi-line, so a
        # line-oriented parse would split one commit across records: the first body line would be
        # swallowed into `subject` and the rest dropped with no error. NUL is the only byte git
        # guarantees cannot appear in a commit message, so it is the only safe record delimiter.
        #
        # The record separator must be git's `%x00` ESCAPE, never a literal NUL: argv strings are
        # NUL-terminated, so the OS would silently truncate the format at that byte and every commit
        # would come back unparsed. US (0x1f) is fine literal — only NUL is impossible to pass.
        sep, rec = "\x1f", "\x00"
        fields = f"%h{sep}%an{sep}%aI{sep}%s" + (f"{sep}%b" if include_body else "")
        try:
            raw = self._git("log", f"-{limit}", f"--format={fields}%x00", branch, repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "log", "error": str(exc)})
            raise

        width = 5 if include_body else 4
        commits = []
        for record in raw.split(rec):
            record = record.strip("\n")  # git writes a newline after each record
            if not record.strip():
                continue
            parts = record.split(sep, width - 1)
            if len(parts) != width:
                continue
            commit = {
                "sha7": parts[0],
                "author": parts[1],
                "date": parts[2],
                "subject": parts[3][:80],  # unchanged contract: subject stays truncated
            }
            if include_body:
                commit["body"] = parts[4].strip()
            commits.append(commit)

        ctx.emit("git_response", {"operation": "log", "count": len(commits)})
        return {"commits": commits, "count": len(commits)}

    # ------------------------------------------------------------------
    # diff_summary
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.diff_summary",
        version="0.1.0",
        description="Diff statistics only — files changed, insertions, deletions. Patch text is NEVER returned.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "base": {"type": "string", "description": "Base ref (e.g. 'main', 'HEAD~1')"},
                "head": {"type": "string", "description": "Head ref (default: working tree)"},
                "staged": {"type": "boolean", "description": "Diff staged changes only"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "diff"],
    )
    async def diff_summary(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        base = payload.get("base")
        head = payload.get("head")
        staged = bool(payload.get("staged", False))
        ctx.emit("git_request", {"operation": "diff_summary", "repo_path": repo, "staged": staged})
        try:
            args = ["diff", "--stat"]
            if staged:
                args.append("--cached")
            if base:
                args.append(base)
            if head:
                args.append(head)
            stat_output = self._git(*args, repo=repo)

            # --shortstat for machine-readable counts
            short_args = ["diff", "--shortstat"]
            if staged:
                short_args.append("--cached")
            if base:
                short_args.append(base)
            if head:
                short_args.append(head)
            short = self._git(*short_args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "diff_summary", "error": str(exc)})
            raise

        files_changed = insertions = deletions = 0
        if short:
            import re
            m = re.search(r"(\d+) file", short)
            if m:
                files_changed = int(m.group(1))
            m = re.search(r"(\d+) insertion", short)
            if m:
                insertions = int(m.group(1))
            m = re.search(r"(\d+) deletion", short)
            if m:
                deletions = int(m.group(1))

        # Extract file names from stat output (not content)
        changed_files: list[str] = []
        for line in stat_output.splitlines():
            parts = line.split("|")
            if len(parts) == 2:
                changed_files.append(parts[0].strip())

        result = {
            "files_changed": files_changed,
            "insertions": insertions,
            "deletions": deletions,
            "changed_files": changed_files,
        }
        ctx.emit("git_response", {"operation": "diff_summary", **result})
        return result

    # ------------------------------------------------------------------
    # precommit_check
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.precommit_check",
        version="0.1.0",
        description="List staged files, count unstaged changes, and flag untracked files.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "precommit", "staged"],
    )
    async def precommit_check(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("git_request", {"operation": "precommit_check", "repo_path": repo})
        try:
            porcelain = self._git("status", "--porcelain", repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "precommit_check", "error": str(exc)})
            raise

        staged_files: list[str] = []
        unstaged_count = 0
        untracked_count = 0
        for line in porcelain.splitlines():
            if len(line) < 3:
                continue
            x, y, path = line[0], line[1], line[3:]
            if x == "?" and y == "?":
                untracked_count += 1
            else:
                if x not in (" ", "?"):
                    staged_files.append(path)
                if y not in (" ", "?"):
                    unstaged_count += 1

        result = {
            "staged_files": staged_files,
            "staged_count": len(staged_files),
            "unstaged_count": unstaged_count,
            "untracked_count": untracked_count,
            "ready_to_commit": len(staged_files) > 0 and unstaged_count == 0,
        }
        ctx.emit("git_response", {"operation": "precommit_check", "staged_count": result["staged_count"], "unstaged_count": unstaged_count})
        return result

    # ------------------------------------------------------------------
    # checkout_branch
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.checkout_branch",
        version="0.1.0",
        description="Create a new branch or switch to an existing one.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "branch": {"type": "string", "description": "Branch name to create or switch to"},
                "create": {"type": "boolean", "description": "Create the branch if it does not exist (default: true)"},
            },
            "required": ["branch"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "branch", "checkout"],
    )
    async def checkout_branch(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        branch = payload["branch"]
        create = bool(payload.get("create", True))
        ctx.emit("git_request", {"operation": "checkout_branch", "branch": branch, "create": create})
        try:
            if create:
                # Try switch, fall back to create
                existing = self._git("branch", "--list", branch, repo=repo)
                if existing:
                    self._git("checkout", branch, repo=repo)
                else:
                    self._git("checkout", "-b", branch, repo=repo)
            else:
                self._git("checkout", branch, repo=repo)
            current = self._git("rev-parse", "--abbrev-ref", "HEAD", repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "checkout_branch", "error": str(exc)})
            raise

        result = {"branch": current, "created": create and current == branch}
        ctx.emit("git_response", {"operation": "checkout_branch", "branch": current})
        return result

    # ------------------------------------------------------------------
    # commit
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.commit",
        version="0.1.0",
        description="Stage specified files and create a commit. Diff content is never in evidence.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "message": {"type": "string", "description": "Commit message"},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File paths to stage (relative to repo root). Empty list stages all tracked changes.",
                },
                "allow_empty": {"type": "boolean", "description": "Allow commit with no changes (default: false)"},
            },
            "required": ["message"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "commit"],
    )
    async def commit(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        message = payload["message"]
        files: list[str] = payload.get("files") or []
        allow_empty = bool(payload.get("allow_empty", False))
        ctx.emit("git_request", {
            "operation": "commit",
            "repo_path": repo,
            "file_count": len(files),
            # message NOT in evidence
        })
        try:
            if files:
                for f in files:
                    self._git("add", f, repo=repo)
            else:
                self._git("add", "-u", repo=repo)

            commit_args = ["commit", "-m", message]
            if allow_empty:
                commit_args.append("--allow-empty")
            self._git(*commit_args, repo=repo)
            sha = self._git("rev-parse", "HEAD", repo=repo)
            sha7 = sha[:7]
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "commit", "error": str(exc)})
            raise

        result = {
            "sha7": sha7,
            "sha": sha[:40],
            "files_staged": len(files),
        }
        ctx.emit("git_response", {"operation": "commit", "sha7": sha7, "files_staged": result["files_staged"]})
        return result

    # ------------------------------------------------------------------
    # discover_repos
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.discover_repos",
        version="0.1.0",
        description="Bounded filesystem walk for git repositories under a root: repo paths "
                    "+ count. Depth- and count-capped; hidden and vendored trees skipped. "
                    "Root defaults to the node's configured scope, so a mesh orchestrator can "
                    "discover repos on ANY node without knowing its local filesystem layout.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "root": {"type": "string",
                         "description": "Directory to scan (defaults to the node's configured scope)"},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 6},
                "max_repos": {"type": "integer", "minimum": 1, "maximum": 500},
                "follow_symlinks": {"type": "boolean",
                                    "description": "Descend symlinked dirs (default true; "
                                                   "max_depth/max_repos still bound the walk)"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "discover", "repositories"],
    )
    async def discover_repos(self, ctx: Any, payload: dict) -> dict:
        # Default to the node's configured scope: a control-plane orchestrator doesn't know each
        # node's local path (Unix vs Windows), so omitting root scans the node's own scope.
        root = os.path.realpath(payload.get("root") or self._config._effective_repo_path())
        max_depth = int(payload.get("max_depth") or 3)
        max_repos = int(payload.get("max_repos") or 200)
        follow = payload.get("follow_symlinks", True)  # symlinked repos (e.g. to external
        # drives) are otherwise never descended; max_depth/max_repos still bound the walk.
        ctx.emit("git_request", {"operation": "discover_repos", "root": root,
                                 "max_depth": max_depth, "follow_symlinks": follow})
        if not os.path.isdir(root):
            ctx.emit("git_error", {"operation": "discover_repos", "error": "root not a directory"})
            raise RuntimeError(f"discover root is not a directory: {root}")

        skip = {"node_modules", ".venv", "venv", "__pycache__", ".cache"}
        repos: list[str] = []
        truncated = False
        for dirpath, dirnames, _files in os.walk(root, followlinks=follow):
            depth = os.path.relpath(dirpath, root).count(os.sep)
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames[:] = []  # a repo's insides are not scanned further
                if len(repos) >= max_repos:
                    truncated = True
                    break
                continue
            if depth >= max_depth - 1:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in skip]

        result = {"root": root, "repos": sorted(repos), "count": len(repos),
                  "truncated": truncated}
        ctx.emit("git_response", {"operation": "discover_repos", "count": len(repos),
                                  "truncated": truncated})
        return result

    # ------------------------------------------------------------------
    # bundle
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.bundle",
        version="0.1.0",
        description="Single-file repository snapshot via `git bundle create --all`, then "
                    "`git bundle verify` and size. Content-hashing of the snapshot belongs "
                    "to whatever transports it (e.g. a governed artifact transfer) — this "
                    "adapter does no raw file IO. Evidence carries counts — never content.",
        category="developer_tooling",
        risk="medium",
        side_effects=["filesystem_write"],
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "dest_path": {"type": "string",
                              "description": "Absolute path the .bundle file is written to"},
            },
            "required": ["dest_path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "bundle", "backup", "snapshot"],
    )
    async def bundle(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        dest = os.path.realpath(payload["dest_path"])
        ctx.emit("git_request", {"operation": "bundle", "repo_path": repo, "dest_path": dest})
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            self._git("bundle", "create", dest, "--all", repo=repo)
            self._git("bundle", "verify", dest, repo=repo)  # integrity before anything trusts it
            head_sha = self._git("rev-parse", "HEAD", repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "bundle", "error": str(exc)})
            raise

        result = {
            "dest_path": dest,
            "size_bytes": os.path.getsize(dest),
            "head_sha7": head_sha[:7],
            "verified": True,
        }
        ctx.emit("git_response", {"operation": "bundle",
                                  "size_bytes": result["size_bytes"],
                                  "head_sha7": result["head_sha7"]})
        return result

    # ------------------------------------------------------------------
    # push
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.push",
        version="0.1.0",
        description="Push a ref to a remote. Evidence: remote, ref, HEAD SHA7, success flag.",
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "remote": {"type": "string", "description": "Remote name (e.g. 'origin', 'github')"},
                "ref": {"type": "string", "description": "Ref to push (branch name, tag, or 'HEAD')"},
                "force": {"type": "boolean", "description": "Force push with --force-with-lease (default: false)"},
                "set_upstream": {"type": "boolean", "description": "Set upstream tracking (-u) (default: false)"},
            },
            "required": ["remote", "ref"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "push", "remote"],
    )
    async def push(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        remote = payload["remote"]
        ref = payload["ref"]
        force = bool(payload.get("force", False))
        set_upstream = bool(payload.get("set_upstream", False))

        ctx.emit("git_request", {"operation": "push", "remote": remote, "ref": ref})
        try:
            sha = self._git("rev-parse", "HEAD", repo=repo)
            sha7 = sha[:7]
            push_args = ["push", remote, ref]
            if force:
                push_args.append("--force-with-lease")
            if set_upstream:
                push_args.extend(["-u"])
            self._git(*push_args, repo=repo)
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "push", "error": str(exc)})
            raise

        result = {"remote": remote, "ref": ref, "head_sha7": sha7, "success": True}
        ctx.emit("git_response", {"operation": "push", "remote": remote, "ref": ref, "head_sha7": sha7})
        return result

    # ------------------------------------------------------------------
    # pull
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.pull",
        version="0.1.0",
        description="Pull from a remote. Evidence: remote, branch, new HEAD SHA7, fast_forward flag.",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "remote": {"type": "string", "description": "Remote name (default: 'origin')"},
                "branch": {"type": "string", "description": "Branch to pull (defaults to current tracking branch)"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "pull", "remote"],
    )
    async def pull(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        remote = payload.get("remote", "origin")
        branch: str | None = payload.get("branch")

        ctx.emit("git_request", {"operation": "pull", "remote": remote, "branch": branch})
        try:
            pull_args = ["pull", remote]
            if branch:
                pull_args.append(branch)
            output = self._git(*pull_args, repo=repo)
            sha = self._git("rev-parse", "HEAD", repo=repo)
            sha7 = sha[:7]
        except RuntimeError as exc:
            ctx.emit("git_error", {"operation": "pull", "error": str(exc)})
            raise

        fast_forward = "Fast-forward" in output
        already_up_to_date = "Already up to date" in output or "Already up-to-date" in output
        result = {
            "remote": remote,
            "branch": branch,
            "head_sha7": sha7,
            "fast_forward": fast_forward,
            "already_up_to_date": already_up_to_date,
        }
        ctx.emit("git_response", {
            "operation": "pull",
            "remote": remote,
            "head_sha7": sha7,
            "fast_forward": fast_forward,
            "already_up_to_date": already_up_to_date,
        })
        return result

    # ------------------------------------------------------------------
    # merge
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.git.merge",
        version="0.1.0",
        description="Merge a branch into the current branch. Evidence: branch, strategy, HEAD SHA7, conflicts flag.",
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "branch": {"type": "string", "description": "Branch to merge"},
                "strategy": {
                    "type": "string",
                    "enum": ["default", "squash", "no-ff"],
                    "description": "Merge strategy (default: 'default')",
                },
                "message": {"type": "string", "description": "Commit message for the merge (NOT in evidence)"},
            },
            "required": ["branch"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["git", "merge"],
    )
    async def merge(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        branch = payload["branch"]
        strategy = payload.get("strategy", "default")
        message: str | None = payload.get("message")

        ctx.emit("git_request", {"operation": "merge", "branch": branch, "strategy": strategy})
        conflicts = False
        try:
            merge_args = ["merge"]
            if strategy == "squash":
                merge_args.append("--squash")
            elif strategy == "no-ff":
                merge_args.append("--no-ff")
            if message:
                merge_args.extend(["-m", message])
            merge_args.append(branch)
            self._git(*merge_args, repo=repo)
            sha = self._git("rev-parse", "HEAD", repo=repo)
            sha7 = sha[:7]
        except RuntimeError as exc:
            error_str = str(exc)
            if "CONFLICT" in error_str or "conflict" in error_str.lower():
                conflicts = True
            ctx.emit("git_error", {"operation": "merge", "error": error_str, "conflicts": conflicts})
            raise

        result = {
            "branch": branch,
            "strategy": strategy,
            "head_sha7": sha7,
            "conflicts": conflicts,
        }
        ctx.emit("git_response", {
            "operation": "merge",
            "branch": branch,
            "strategy": strategy,
            "head_sha7": sha7,
        })
        return result
