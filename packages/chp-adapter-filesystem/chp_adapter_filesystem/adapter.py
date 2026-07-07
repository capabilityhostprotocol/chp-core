"""FilesystemAdapter — governed file read/write/list as CHP capabilities.

Safety invariants (MUST PRESERVE):
* Every path is resolved via ``Path(path).resolve()`` before use.
* If ``allowed_roots`` is set, resolved path must start with one of the roots.
* File content is NEVER stored in evidence — only path, size, and metadata.
* ``max_read_bytes`` and ``max_write_bytes`` cap I/O to prevent runaway reads.
* grep match text and glob file lists are NOT stored in evidence — only counts.

Six capabilities:

* ``read_file``      — read a file's content (UTF-8 or specified encoding)
* ``write_file``     — write or overwrite a file; optionally create parent dirs
* ``list_directory`` — list entries in a directory with optional glob pattern
* ``stat_path``      — check existence, type, and size of a path
* ``grep``           — search files by regex pattern (uses grep/rg)
* ``glob_files``     — recursive glob file discovery
"""

from __future__ import annotations

import fnmatch
import glob as _glob
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "fs_read", "fs_write", "fs_list", "fs_stat",
    "fs_grep", "fs_glob",
    "fs_error", "fs_access_denied",
]

_MAX_GREP_RESULTS = 200
_MAX_GLOB_RESULTS = 500


def _is_within(path: Path, root: Path) -> bool:
    """True if *path* is *root* or lives under it — component-wise, not string
    prefix (so '/srv/data-secret' is not 'within' '/srv/data')."""
    try:
        return path == root or path.is_relative_to(root)
    except AttributeError:  # Python < 3.9
        import os
        try:
            return os.path.commonpath([str(path), str(root)]) == str(root)
        except ValueError:
            return False


@dataclass
class FilesystemConfig:
    """Config for FilesystemAdapter.

    ``allowed_roots`` — if non-None, all paths must resolve under one of
    these roots (prevents escaping a sandbox). Values are resolved at check
    time, so relative roots are resolved relative to CWD at call time.

    ``max_read_bytes`` / ``max_write_bytes`` — size guards; operations that
    would exceed these limits return failure.
    """

    allowed_roots: list[str] | None = None
    max_read_bytes: int = 1 * 1024 * 1024    # 1 MB
    max_write_bytes: int = 512 * 1024         # 512 KB


class FilesystemAdapter(BaseAdapter):
    """Governed file read/write/list with path allowlist."""

    adapter_id = "chp.adapters.filesystem"
    adapter_name = "Filesystem"
    adapter_description = "Governed file system access with configurable path restrictions."
    adapter_category = "execution"
    adapter_tags = ["filesystem", "files", "io"]

    def __init__(self, config: FilesystemConfig | None = None) -> None:
        self._config = config or FilesystemConfig()

    # ------------------------------------------------------------------
    # Internal path safety
    # ------------------------------------------------------------------

    def _check_path(self, path: str) -> Path:
        """Resolve *path* and verify it is under an allowed root (if configured)."""
        resolved = Path(path).resolve()
        if self._config.allowed_roots is not None:
            # Component-wise containment, NOT string prefix: root '/srv/data'
            # must not admit sibling '/srv/data-secret'. is_relative_to compares
            # path parts, so '/srv/data-secret' is correctly rejected.
            allowed = [Path(r).resolve() for r in self._config.allowed_roots]
            if not any(_is_within(resolved, a) for a in allowed):
                raise PermissionError(
                    f"Path {resolved} is outside allowed roots"
                )
        return resolved

    # ------------------------------------------------------------------
    # read_file
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.read_file",
        version="1.0.0",
        description="Read a file's content.",
        category="execution",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read."},
                "encoding": {
                    "type": "string",
                    "description": "Text encoding (default utf-8).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem", "read"],
    )
    async def read_file(self, ctx: Any, payload: dict) -> dict:
        encoding = payload.get("encoding", "utf-8")
        try:
            resolved = self._check_path(payload["path"])
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": payload["path"], "reason": str(exc)},
                     redacted=False)
            raise

        if not resolved.exists():
            ctx.emit("fs_error", {
                "op": "read_file", "path": str(resolved), "reason": "not_found",
            }, redacted=False)
            raise FileNotFoundError(f"File not found: {resolved}")

        if not resolved.is_file():
            ctx.emit("fs_error", {
                "op": "read_file", "path": str(resolved), "reason": "not_a_file",
            }, redacted=False)
            raise IsADirectoryError(f"Path is a directory: {resolved}")

        size = resolved.stat().st_size
        if size > self._config.max_read_bytes:
            ctx.emit("fs_error", {
                "op": "read_file", "path": str(resolved),
                "reason": "file_too_large",
                "size_bytes": size,
                "max_read_bytes": self._config.max_read_bytes,
            }, redacted=False)
            raise ValueError(
                f"File too large to read: {size} bytes > max {self._config.max_read_bytes}"
            )

        content = resolved.read_text(encoding=encoding)

        ctx.emit("fs_read", {
            "path": str(resolved),
            "size_bytes": size,
            "encoding": encoding,
        }, redacted=False)

        return {"path": str(resolved), "content": content, "size_bytes": size, "encoding": encoding}

    # ------------------------------------------------------------------
    # write_file
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.write_file",
        version="1.0.0",
        description="Write or overwrite a file.",
        category="execution",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write."},
                "content": {"type": "string", "description": "Text content to write."},
                "encoding": {"type": "string", "description": "Text encoding (default utf-8)."},
                "create_parents": {
                    "type": "boolean",
                    "description": "Create parent directories if they don't exist.",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem", "write"],
    )
    async def write_file(self, ctx: Any, payload: dict) -> dict:
        encoding = payload.get("encoding", "utf-8")
        create_parents = payload.get("create_parents", False)
        content = payload["content"]

        encoded = content.encode(encoding)
        if len(encoded) > self._config.max_write_bytes:
            ctx.emit("fs_error", {
                "op": "write_file", "path": payload["path"],
                "reason": "content_too_large",
                "size_bytes": len(encoded),
                "max_write_bytes": self._config.max_write_bytes,
            }, redacted=False)
            raise ValueError(
                f"Content too large to write: {len(encoded)} bytes > max {self._config.max_write_bytes}"
            )

        try:
            resolved = self._check_path(payload["path"])
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": payload["path"], "reason": str(exc)},
                     redacted=False)
            raise

        created = not resolved.exists()
        if create_parents:
            resolved.parent.mkdir(parents=True, exist_ok=True)

        resolved.write_text(content, encoding=encoding)

        ctx.emit("fs_write", {
            "path": str(resolved),
            "written_bytes": len(encoded),
            "created": created,
        }, redacted=False)

        return {"path": str(resolved), "written_bytes": len(encoded), "created": created}

    # ------------------------------------------------------------------
    # list_directory
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.list_directory",
        version="1.0.0",
        description="List entries in a directory.",
        category="execution",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path to list."},
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to filter entries (e.g. '*.py').",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem", "list"],
    )
    async def list_directory(self, ctx: Any, payload: dict) -> dict:
        pattern = payload.get("pattern")

        try:
            resolved = self._check_path(payload["path"])
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": payload["path"], "reason": str(exc)},
                     redacted=False)
            raise

        if not resolved.exists():
            ctx.emit("fs_error", {
                "op": "list_directory", "path": str(resolved), "reason": "not_found",
            }, redacted=False)
            raise FileNotFoundError(f"Directory not found: {resolved}")

        if not resolved.is_dir():
            ctx.emit("fs_error", {
                "op": "list_directory", "path": str(resolved), "reason": "not_a_directory",
            }, redacted=False)
            raise NotADirectoryError(f"Path is not a directory: {resolved}")

        entries = []
        for child in sorted(resolved.iterdir()):
            if pattern and not fnmatch.fnmatch(child.name, pattern):
                continue
            entry_type = "directory" if child.is_dir() else "file"
            try:
                size = child.stat().st_size if child.is_file() else None
            except OSError:
                size = None
            entries.append({"name": child.name, "type": entry_type, "size_bytes": size})

        ctx.emit("fs_list", {
            "path": str(resolved),
            "pattern": pattern,
            "count": len(entries),
        }, redacted=False)

        return {"path": str(resolved), "entries": entries, "count": len(entries)}

    # ------------------------------------------------------------------
    # stat_path
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.stat_path",
        version="1.0.0",
        description="Check existence, type, and size of a path.",
        category="execution",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to stat."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem"],
    )
    async def stat_path(self, ctx: Any, payload: dict) -> dict:
        try:
            resolved = self._check_path(payload["path"])
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": payload["path"], "reason": str(exc)},
                     redacted=False)
            raise

        if not resolved.exists():
            ctx.emit("fs_stat", {"path": str(resolved), "exists": False}, redacted=False)
            return {"path": str(resolved), "exists": False, "type": None,
                    "size_bytes": None, "modified_at": None}

        stat = resolved.stat()
        entry_type = "directory" if resolved.is_dir() else "file"
        import datetime
        modified_at = datetime.datetime.fromtimestamp(
            stat.st_mtime, tz=datetime.timezone.utc
        ).isoformat()

        ctx.emit("fs_stat", {
            "path": str(resolved),
            "exists": True,
            "type": entry_type,
            "size_bytes": stat.st_size,
        }, redacted=False)

        return {
            "path": str(resolved),
            "exists": True,
            "type": entry_type,
            "size_bytes": stat.st_size,
            "modified_at": modified_at,
        }

    # ------------------------------------------------------------------
    # grep
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.grep",
        version="1.0.0",
        description=(
            "Search files for a regex pattern. Uses ripgrep (rg) when available, "
            "falls back to grep. Returns up to 200 matches with file, line number, "
            "and matched text. Match content is NOT stored in evidence."
        ),
        category="execution",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for."},
                "path": {"type": "string", "description": "Directory or file to search."},
                "glob": {"type": "string", "description": "File glob filter, e.g. '*.py'."},
                "case_insensitive": {"type": "boolean", "description": "Case-insensitive search."},
            },
            "required": ["pattern", "path"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem", "search"],
    )
    async def grep(self, ctx: Any, payload: dict) -> dict:
        pattern = payload["pattern"]
        glob_filter = payload.get("glob")
        case_insensitive = payload.get("case_insensitive", False)

        try:
            resolved = self._check_path(payload["path"])
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": payload["path"], "reason": str(exc)}, redacted=False)
            raise

        t0 = time.monotonic()
        use_rg = shutil.which("rg") is not None

        if use_rg:
            cmd = ["rg", "--line-number", "--no-heading", "--color=never"]
            if case_insensitive:
                cmd.append("-i")
            if glob_filter:
                cmd.extend(["-g", glob_filter])
            cmd.extend([pattern, str(resolved)])
        else:
            cmd = ["grep", "-rn"]
            if case_insensitive:
                cmd.append("-i")
            if glob_filter:
                cmd.extend([f"--include={glob_filter}"])
            cmd.extend([pattern, str(resolved)])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            ctx.emit("fs_error", {"op": "grep", "path": str(resolved), "reason": "timeout"}, redacted=False)
            raise TimeoutError(f"grep timed out searching {resolved}")

        matches = []
        truncated = False
        for line in proc.stdout.splitlines():
            if len(matches) >= _MAX_GREP_RESULTS:
                truncated = True
                break
            # rg and grep -n both output: file:line:text
            parts = line.split(":", 2)
            if len(parts) >= 3:
                matches.append({"file": parts[0], "line_no": parts[1], "text": parts[2]})
            elif len(parts) == 2:
                matches.append({"file": parts[0], "line_no": parts[1], "text": ""})

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("fs_grep", {
            "path": str(resolved),
            "pattern": pattern,
            "glob": glob_filter,
            "match_count": len(matches),
            "truncated": truncated,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {"matches": matches, "match_count": len(matches), "truncated": truncated}

    # ------------------------------------------------------------------
    # glob_files
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.filesystem.glob_files",
        version="1.0.0",
        description=(
            "Recursively discover files matching a glob pattern. "
            "Supports ** for recursive matching. Returns up to 500 file paths."
        ),
        category="execution",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern, e.g. '**/*.py'."},
                "base_path": {"type": "string", "description": "Base directory to search from (default: CWD)."},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["filesystem", "search"],
    )
    async def glob_files(self, ctx: Any, payload: dict) -> dict:
        pattern = payload["pattern"]
        base_path = payload.get("base_path", ".")

        try:
            resolved_base = self._check_path(base_path)
        except PermissionError as exc:
            ctx.emit("fs_access_denied", {"path": base_path, "reason": str(exc)}, redacted=False)
            raise

        t0 = time.monotonic()
        raw = _glob.glob(pattern, root_dir=str(resolved_base), recursive=True)
        # A pattern like '../../etc/*' escapes root_dir — re-validate every
        # returned path against the allowed roots, dropping any that resolve out.
        if self._config.allowed_roots is not None:
            kept = []
            for rel in raw:
                try:
                    self._check_path(str(resolved_base / rel))
                except PermissionError:
                    continue
                kept.append(rel)
            raw = kept
        raw.sort()

        truncated = len(raw) > _MAX_GLOB_RESULTS
        files = raw[:_MAX_GLOB_RESULTS]

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("fs_glob", {
            "pattern": pattern,
            "base_path": str(resolved_base),
            "count": len(files),
            "truncated": truncated,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {"files": files, "count": len(files), "truncated": truncated}
