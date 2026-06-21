"""ReleaseAdapter — release pipeline operations as CHP capabilities.

Evidence hygiene (MUST PRESERVE):
* Build output, upload logs, npm publish output — NEVER in evidence; only
  package name, version, repository URL.
* Diff/stat output from sync — NEVER in evidence; only PR URL/number.
* Commit messages — NEVER in evidence.
* Tokens or credential values — NEVER in evidence.

Five capabilities:

* ``bump``         — update version in pyproject.toml and package.json (no commit)
* ``sync``         — run sync-to-public.sh; evidence: PR URL/number only
* ``tag``          — create a git tag and push it; governed path for version tagging
* ``publish_pypi`` — build + twine upload; evidence: name, version, registry
* ``publish_npm``  — npm publish; evidence: name, version, tag, registry
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from chp_core import BaseAdapter, capability

_EMITS = ["release_request", "release_response", "release_error"]


# ---------------------------------------------------------------------------
# Injectable backend
# ---------------------------------------------------------------------------

@runtime_checkable
class ProcessBackend(Protocol):
    """Minimal interface for running arbitrary shell commands."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        """Run the command and return stdout. Raises RuntimeError on non-zero exit."""
        ...


class SubprocessProcessBackend:
    """Production backend: runs commands via subprocess."""

    def run(self, *args: str, cwd: str | None = None) -> str:
        result = subprocess.run(
            list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"{args[0]} failed")
        return result.stdout.strip()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class ReleaseConfig:
    """Config for ReleaseAdapter.

    ``default_repo_path`` can be overridden per-call via ``repo_path`` payload field.
    ``backend`` accepts a test double for unit isolation.
    """

    default_repo_path: str | None = None
    backend: Any = None

    def _effective_repo_path(self) -> str:
        return self.default_repo_path or os.getcwd()

    def _effective_backend(self) -> ProcessBackend:
        return self.backend if self.backend is not None else SubprocessProcessBackend()


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class ReleaseAdapter(BaseAdapter):
    """Release pipeline operations: version bump, sync, tag, publish."""

    adapter_id = "chp.adapters.release"
    adapter_name = "Release"
    adapter_description = "Release pipeline: bump versions, sync to public, tag, publish to PyPI and npm"
    adapter_category = "developer_tooling"
    adapter_tags = ["release", "publish", "pypi", "npm", "versioning", "sync"]

    def __init__(self, config: ReleaseConfig | None = None) -> None:
        self._config = config or ReleaseConfig()

    def _backend(self) -> ProcessBackend:
        return self._config._effective_backend()

    def _repo(self, payload: dict) -> str:
        return payload.get("repo_path") or self._config._effective_repo_path()

    def _run(self, *args: str, cwd: str | None = None) -> str:
        return self._backend().run(*args, cwd=cwd)

    # ------------------------------------------------------------------
    # bump
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.release.bump",
        version="0.1.0",
        description=(
            "Update version string in pyproject.toml and/or package.json. "
            "Does not commit — use git.commit after."
        ),
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "version": {"type": "string", "description": "New version string (e.g. '0.8.0')"},
                "repo_path": {"type": "string"},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Relative paths to files to update. "
                        "Defaults to ['packages/python/pyproject.toml', 'packages/ts-types/package.json']."
                    ),
                },
            },
            "required": ["version"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["release", "version", "bump"],
    )
    async def bump(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        new_version = payload["version"]
        default_files = [
            "packages/python/pyproject.toml",
            "packages/ts-types/package.json",
        ]
        target_files: list[str] = payload.get("files") or default_files

        ctx.emit("release_request", {
            "operation": "bump",
            "version": new_version,
            "file_count": len(target_files),
        })

        updated: list[str] = []
        old_version: str | None = None

        for rel_path in target_files:
            path = Path(repo) / rel_path
            if not path.exists():
                continue
            content = path.read_text()

            if rel_path.endswith("pyproject.toml"):
                m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
                if m:
                    if old_version is None:
                        old_version = m.group(1)
                    content = re.sub(
                        r'^(version\s*=\s*)"[^"]+"',
                        f'\\1"{new_version}"',
                        content,
                        flags=re.MULTILINE,
                    )
                    path.write_text(content)
                    updated.append(rel_path)

            elif rel_path.endswith("package.json"):
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    continue
                if "version" in data:
                    if old_version is None:
                        old_version = data["version"]
                    data["version"] = new_version
                    path.write_text(json.dumps(data, indent=2) + "\n")
                    updated.append(rel_path)

        result = {
            "old_version": old_version,
            "new_version": new_version,
            "files_updated": updated,
            "files_updated_count": len(updated),
        }
        ctx.emit("release_response", {
            "operation": "bump",
            "old_version": old_version,
            "new_version": new_version,
            "files_updated_count": len(updated),
        })
        return result

    # ------------------------------------------------------------------
    # sync
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.release.sync",
        version="0.1.0",
        description=(
            "Run scripts/sync-to-public.sh to sync chp-dev → chp-core and open a PR. "
            "Evidence contains only PR URL and number — diff/stat output is NOT captured."
        ),
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "dry_run": {
                    "type": "boolean",
                    "description": "Show what would change without writing (default: false)",
                },
                "branch": {
                    "type": "string",
                    "description": "PR branch name (e.g. 'release/v0.8.0'); auto-generated if omitted",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["release", "sync", "pr", "chp-core"],
    )
    async def sync(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        dry_run = bool(payload.get("dry_run", False))
        branch: str | None = payload.get("branch")

        ctx.emit("release_request", {"operation": "sync", "dry_run": dry_run})

        try:
            args = ["bash", "scripts/sync-to-public.sh"]
            if dry_run:
                args.append("--dry-run")
            else:
                args.append("--pr")
                if branch:
                    args.append(branch)
            output = self._run(*args, cwd=repo)
        except RuntimeError as exc:
            ctx.emit("release_error", {"operation": "sync", "error": str(exc)})
            raise

        pr_url: str | None = None
        pr_number: int | None = None
        m = re.search(r"https://github\.com/[^\s]+/pull/(\d+)", output)
        if m:
            pr_url = m.group(0)
            pr_number = int(m.group(1))

        result: dict = {
            "dry_run": dry_run,
            "pr_url": pr_url,
            "pr_number": pr_number,
            "success": True,
        }
        ctx.emit("release_response", {
            "operation": "sync",
            "pr_url": pr_url,
            "pr_number": pr_number,
            "dry_run": dry_run,
        })
        return result

    # ------------------------------------------------------------------
    # tag
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.release.tag",
        version="0.1.0",
        description=(
            "Create a git version tag and optionally push it. "
            "This is the governed path — raw 'git tag v*' via bash is policy-blocked."
        ),
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "tag_name": {"type": "string", "description": "Tag name (e.g. 'v0.8.0')"},
                "push": {
                    "type": "boolean",
                    "description": "Push the tag to the remote after creation (default: true)",
                },
                "remote": {
                    "type": "string",
                    "description": "Remote to push to (default: 'github')",
                },
            },
            "required": ["tag_name"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["release", "tag", "git"],
    )
    async def tag(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        tag_name = payload["tag_name"]
        push = bool(payload.get("push", True))
        remote = payload.get("remote", "github")

        ctx.emit("release_request", {
            "operation": "tag",
            "tag_name": tag_name,
            "push": push,
            "remote": remote,
        })
        try:
            sha = self._run("git", "rev-parse", "HEAD", cwd=repo)
            sha7 = sha[:7]
            self._run("git", "tag", tag_name, cwd=repo)
            pushed = False
            if push:
                self._run("git", "push", remote, tag_name, cwd=repo)
                pushed = True
        except RuntimeError as exc:
            ctx.emit("release_error", {"operation": "tag", "error": str(exc)})
            raise

        result = {
            "tag_name": tag_name,
            "commit_sha7": sha7,
            "commit_sha": sha[:40],
            "pushed": pushed,
            "remote": remote if pushed else None,
        }
        ctx.emit("release_response", {
            "operation": "tag",
            "tag_name": tag_name,
            "commit_sha7": sha7,
            "pushed": pushed,
        })
        return result

    # ------------------------------------------------------------------
    # publish_pypi
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.release.publish_pypi",
        version="0.1.0",
        description=(
            "Build and upload a Python package to PyPI or TestPyPI. "
            "Build/upload output is NOT in evidence — only package name, version, registry."
        ),
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "package_dir": {
                    "type": "string",
                    "description": "Path to package dir relative to repo_path (default: 'packages/python')",
                },
                "repository": {
                    "type": "string",
                    "enum": ["pypi", "testpypi"],
                    "description": "Target registry (default: 'pypi')",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["release", "pypi", "publish", "python"],
    )
    async def publish_pypi(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        package_dir = payload.get("package_dir", "packages/python")
        repository = payload.get("repository", "pypi")
        pkg_path = Path(repo) / package_dir

        name = version = "unknown"
        pyproject_path = pkg_path / "pyproject.toml"
        if pyproject_path.exists():
            content = pyproject_path.read_text()
            m_name = re.search(r'^name\s*=\s*"([^"]+)"', content, re.MULTILINE)
            m_ver = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
            if m_name:
                name = m_name.group(1)
            if m_ver:
                version = m_ver.group(1)

        ctx.emit("release_request", {
            "operation": "publish_pypi",
            "package_name": name,
            "version": version,
            "repository": repository,
        })
        try:
            self._run("python", "-m", "build", cwd=str(pkg_path))

            dist_files = sorted(glob.glob(str(pkg_path / "dist" / "*")))
            if not dist_files:
                raise RuntimeError("No dist files found after build — check build output")

            upload_args = ["python", "-m", "twine", "upload"]
            if repository == "testpypi":
                upload_args.extend(["--repository", "testpypi"])
            upload_args.extend(dist_files)
            self._run(*upload_args, cwd=str(pkg_path))
        except RuntimeError as exc:
            ctx.emit("release_error", {"operation": "publish_pypi", "error": str(exc)})
            raise

        index_url = (
            "https://test.pypi.org/simple/"
            if repository == "testpypi"
            else "https://pypi.org/simple/"
        )
        result = {
            "package_name": name,
            "version": version,
            "repository": repository,
            "index_url": index_url,
            "success": True,
        }
        ctx.emit("release_response", {
            "operation": "publish_pypi",
            "package_name": name,
            "version": version,
            "repository": repository,
        })
        return result

    # ------------------------------------------------------------------
    # publish_npm
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.release.publish_npm",
        version="0.1.0",
        description=(
            "Run npm publish for a TypeScript/JavaScript package. "
            "Publish output is NOT in evidence — only name, version, tag, registry."
        ),
        category="developer_tooling",
        risk="high",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "package_dir": {
                    "type": "string",
                    "description": "Path to package dir relative to repo_path (default: 'packages/ts-types')",
                },
                "tag": {
                    "type": "string",
                    "description": "npm dist-tag (e.g. 'latest', 'next')",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Run with --dry-run to verify without publishing (default: false)",
                },
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["release", "npm", "publish", "javascript"],
    )
    async def publish_npm(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        package_dir = payload.get("package_dir", "packages/ts-types")
        tag: str | None = payload.get("tag")
        dry_run = bool(payload.get("dry_run", False))
        pkg_path = Path(repo) / package_dir

        name = version = "unknown"
        pkg_json_path = pkg_path / "package.json"
        if pkg_json_path.exists():
            try:
                data = json.loads(pkg_json_path.read_text())
                name = data.get("name", "unknown")
                version = data.get("version", "unknown")
            except json.JSONDecodeError:
                pass

        ctx.emit("release_request", {
            "operation": "publish_npm",
            "package_name": name,
            "version": version,
            "dry_run": dry_run,
        })
        try:
            args = ["npm", "publish"]
            if tag:
                args.extend(["--tag", tag])
            if dry_run:
                args.append("--dry-run")
            self._run(*args, cwd=str(pkg_path))
        except RuntimeError as exc:
            ctx.emit("release_error", {"operation": "publish_npm", "error": str(exc)})
            raise

        result = {
            "package_name": name,
            "version": version,
            "tag": tag or "latest",
            "registry_url": "https://registry.npmjs.org/",
            "dry_run": dry_run,
            "success": True,
        }
        ctx.emit("release_response", {
            "operation": "publish_npm",
            "package_name": name,
            "version": version,
            "tag": tag or "latest",
        })
        return result
