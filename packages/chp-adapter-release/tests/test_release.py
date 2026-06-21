"""Tests for ReleaseAdapter.

Uses FakeProcessBackend for subprocess operations; real tmp files for file I/O.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_release import ReleaseAdapter, ReleaseConfig, SubprocessProcessBackend


# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------

class FakeProcessBackend:
    """Records calls and returns scripted responses."""

    def __init__(self, responses: dict[tuple, str] | None = None, default: str = "") -> None:
        self._responses = responses or {}
        self._default = default
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str, cwd: str | None = None) -> str:
        self.calls.append(args)
        return self._responses.get(args, self._default)


def _make_host(backend: FakeProcessBackend, repo_path: str = "/fake/repo") -> LocalCapabilityHost:
    config = ReleaseConfig(default_repo_path=repo_path, backend=backend)
    adapter = ReleaseAdapter(config=config)
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _domain_events(host: LocalCapabilityHost) -> list[dict]:
    return [e for e in host.store.all() if "capability_uri" not in e.get("payload", {})]


# ---------------------------------------------------------------------------
# bump
# ---------------------------------------------------------------------------

class TestBump:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        python_pkg = tmp_path / "packages" / "python"
        python_pkg.mkdir(parents=True)
        (python_pkg / "pyproject.toml").write_text(
            '[project]\nname = "chp-core"\nversion = "0.7.0"\n'
        )
        ts_pkg = tmp_path / "packages" / "ts-types"
        ts_pkg.mkdir(parents=True)
        (ts_pkg / "package.json").write_text(
            json.dumps({"name": "@chp/types", "version": "0.7.0"}) + "\n"
        )
        return tmp_path

    async def test_bumps_pyproject_version(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        assert result.outcome == "success"
        assert result.data["new_version"] == "0.8.0"
        assert result.data["old_version"] == "0.7.0"
        content = (repo / "packages" / "python" / "pyproject.toml").read_text()
        assert 'version = "0.8.0"' in content
        assert 'version = "0.7.0"' not in content

    async def test_bumps_package_json_version(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        data = json.loads((repo / "packages" / "ts-types" / "package.json").read_text())
        assert data["version"] == "0.8.0"

    async def test_files_updated_count(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        assert result.data["files_updated_count"] == 2

    async def test_missing_version_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.bump", {})
        assert result.outcome == "denied"

    async def test_unknown_field_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0", "force": True})
        assert result.outcome == "denied"

    async def test_custom_files_list(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.bump", {
            "version": "0.8.0",
            "files": ["packages/python/pyproject.toml"],
        })
        assert result.data["files_updated_count"] == 1
        assert "packages/python/pyproject.toml" in result.data["files_updated"]

    async def test_skips_missing_files(self) -> None:
        host = _make_host(FakeProcessBackend(), repo_path="/nonexistent")
        result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        assert result.outcome == "success"
        assert result.data["files_updated_count"] == 0
        assert result.data["old_version"] is None

    async def test_evidence_emitted(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        evs = _domain_events(host)
        types = [e["event_type"] for e in evs]
        assert "release_request" in types
        assert "release_response" in types

    async def test_outcome_success(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
        assert result.outcome == "success"


# ---------------------------------------------------------------------------
# tag
# ---------------------------------------------------------------------------

_SHA = "abc1234567890abcdef1234567890abcdef12345"


class TestTag:
    @pytest.fixture
    def backend(self) -> FakeProcessBackend:
        return FakeProcessBackend(responses={
            ("git", "rev-parse", "HEAD"): _SHA,
            ("git", "tag", "v0.8.0"): "",
            ("git", "push", "github", "v0.8.0"): "",
        })

    async def test_creates_and_pushes_tag(self, backend: FakeProcessBackend) -> None:
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0"})
        assert result.outcome == "success"
        assert result.data["tag_name"] == "v0.8.0"
        assert result.data["commit_sha7"] == _SHA[:7]
        assert result.data["commit_sha"] == _SHA[:40]
        assert result.data["pushed"] is True
        assert result.data["remote"] == "github"

    async def test_tag_no_push(self) -> None:
        backend = FakeProcessBackend(responses={
            ("git", "rev-parse", "HEAD"): _SHA,
            ("git", "tag", "v0.8.0"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0", "push": False})
        assert result.outcome == "success"
        assert result.data["pushed"] is False
        assert result.data["remote"] is None
        assert ("git", "push", "github", "v0.8.0") not in backend.calls

    async def test_custom_remote(self) -> None:
        backend = FakeProcessBackend(responses={
            ("git", "rev-parse", "HEAD"): _SHA,
            ("git", "tag", "v0.8.0"): "",
            ("git", "push", "origin", "v0.8.0"): "",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0", "remote": "origin"})
        assert result.data["remote"] == "origin"

    async def test_missing_tag_name_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.tag", {})
        assert result.outcome == "denied"

    async def test_unknown_field_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0", "force": True})
        assert result.outcome == "denied"

    async def test_git_error_propagates(self) -> None:
        class ErrorBackend:
            def run(self, *args: str, cwd: str | None = None) -> str:
                raise RuntimeError("tag already exists")

        config = ReleaseConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = ReleaseAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0"})
        assert result.outcome == "failure"

    async def test_sha_in_evidence(self, backend: FakeProcessBackend) -> None:
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0"})
        evs = _domain_events(host)
        resp = next(e for e in evs if e["event_type"] == "release_response")
        assert resp["payload"]["commit_sha7"] == _SHA[:7]

    async def test_outcome_success(self, backend: FakeProcessBackend) -> None:
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0"})
        assert result.outcome == "success"


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

class TestSync:
    async def test_dry_run(self) -> None:
        backend = FakeProcessBackend(responses={
            ("bash", "scripts/sync-to-public.sh", "--dry-run"): (
                "=== DRY RUN — no files will be written ===\n=== Dry run complete ==="
            ),
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.sync", {"dry_run": True})
        assert result.outcome == "success"
        assert result.data["dry_run"] is True
        assert result.data["pr_url"] is None
        assert result.data["pr_number"] is None

    async def test_pr_url_extracted(self) -> None:
        pr_url = "https://github.com/capabilityhostprotocol/chp-core/pull/3"
        backend = FakeProcessBackend(responses={
            ("bash", "scripts/sync-to-public.sh", "--pr"): f"PR opened.\n{pr_url}\n",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.sync", {})
        assert result.data["pr_url"] == pr_url
        assert result.data["pr_number"] == 3

    async def test_custom_branch(self) -> None:
        backend = FakeProcessBackend(responses={
            ("bash", "scripts/sync-to-public.sh", "--pr", "release/v0.8.0"): "PR opened.",
        })
        host = _make_host(backend)
        result = await host.ainvoke("chp.adapters.release.sync", {"branch": "release/v0.8.0"})
        assert result.outcome == "success"
        assert result.data["success"] is True

    async def test_unknown_field_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.sync", {"force": True})
        assert result.outcome == "denied"

    async def test_error_propagates(self) -> None:
        class ErrorBackend:
            def run(self, *args: str, cwd: str | None = None) -> str:
                raise RuntimeError("chp-core not found")

        config = ReleaseConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = ReleaseAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.release.sync", {})
        assert result.outcome == "failure"

    async def test_evidence_has_pr_url(self) -> None:
        pr_url = "https://github.com/capabilityhostprotocol/chp-core/pull/5"
        backend = FakeProcessBackend(responses={
            ("bash", "scripts/sync-to-public.sh", "--pr"): f"done\n{pr_url}",
        })
        host = _make_host(backend)
        await host.ainvoke("chp.adapters.release.sync", {})
        evs = _domain_events(host)
        resp = next(e for e in evs if e["event_type"] == "release_response")
        assert resp["payload"]["pr_url"] == pr_url
        assert resp["payload"]["pr_number"] == 5


# ---------------------------------------------------------------------------
# publish_pypi
# ---------------------------------------------------------------------------

class TestPublishPypi:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        python_pkg = tmp_path / "packages" / "python"
        python_pkg.mkdir(parents=True)
        (python_pkg / "pyproject.toml").write_text(
            '[project]\nname = "chp-core"\nversion = "0.8.0"\n'
        )
        dist = python_pkg / "dist"
        dist.mkdir()
        (dist / "chp_core-0.8.0-py3-none-any.whl").write_text("fake wheel")
        (dist / "chp_core-0.8.0.tar.gz").write_text("fake sdist")
        return tmp_path

    async def test_reads_package_metadata(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {})
        assert result.outcome == "success"
        assert result.data["package_name"] == "chp-core"
        assert result.data["version"] == "0.8.0"

    async def test_testpypi_index_url(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {"repository": "testpypi"})
        assert result.outcome == "success"
        assert result.data["index_url"] == "https://test.pypi.org/simple/"

    async def test_pypi_index_url(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {})
        assert result.data["index_url"] == "https://pypi.org/simple/"

    async def test_repository_in_result(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {"repository": "testpypi"})
        assert result.data["repository"] == "testpypi"

    async def test_unknown_field_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {"token": "secret"})
        assert result.outcome == "denied"

    async def test_no_secrets_in_evidence(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        await host.ainvoke("chp.adapters.release.publish_pypi", {})
        dump = str([e["payload"] for e in host.store.all()])
        assert "pypi_token" not in dump
        assert "password" not in dump.lower()

    async def test_error_propagates(self) -> None:
        class ErrorBackend:
            def run(self, *args: str, cwd: str | None = None) -> str:
                raise RuntimeError("build failed")

        config = ReleaseConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = ReleaseAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {})
        assert result.outcome == "failure"

    async def test_outcome_success(self, repo: Path) -> None:
        host = _make_host(FakeProcessBackend(), repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_pypi", {})
        assert result.outcome == "success"
        assert result.data["success"] is True


# ---------------------------------------------------------------------------
# publish_npm
# ---------------------------------------------------------------------------

class TestPublishNpm:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        ts_pkg = tmp_path / "packages" / "ts-types"
        ts_pkg.mkdir(parents=True)
        (ts_pkg / "package.json").write_text(
            json.dumps({"name": "@capabilityhostprotocol/types", "version": "0.8.0"}) + "\n"
        )
        return tmp_path

    async def test_reads_package_metadata(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish"): ""})
        host = _make_host(backend, repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_npm", {})
        assert result.outcome == "success"
        assert result.data["package_name"] == "@capabilityhostprotocol/types"
        assert result.data["version"] == "0.8.0"

    async def test_dry_run_flag(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish", "--dry-run"): ""})
        host = _make_host(backend, repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_npm", {"dry_run": True})
        assert result.outcome == "success"
        assert result.data["dry_run"] is True
        assert ("npm", "publish", "--dry-run") in backend.calls

    async def test_custom_tag(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish", "--tag", "next"): ""})
        host = _make_host(backend, repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_npm", {"tag": "next"})
        assert result.outcome == "success"
        assert result.data["tag"] == "next"
        assert ("npm", "publish", "--tag", "next") in backend.calls

    async def test_default_tag_is_latest(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish"): ""})
        host = _make_host(backend, repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_npm", {})
        assert result.data["tag"] == "latest"

    async def test_registry_url_in_result(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish"): ""})
        host = _make_host(backend, repo_path=str(repo))
        result = await host.ainvoke("chp.adapters.release.publish_npm", {})
        assert result.data["registry_url"] == "https://registry.npmjs.org/"

    async def test_unknown_field_denied(self) -> None:
        host = _make_host(FakeProcessBackend())
        result = await host.ainvoke("chp.adapters.release.publish_npm", {"token": "secret"})
        assert result.outcome == "denied"

    async def test_error_propagates(self) -> None:
        class ErrorBackend:
            def run(self, *args: str, cwd: str | None = None) -> str:
                raise RuntimeError("403 forbidden")

        config = ReleaseConfig(default_repo_path="/fake", backend=ErrorBackend())
        adapter = ReleaseAdapter(config=config)
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, adapter)
        result = await host.ainvoke("chp.adapters.release.publish_npm", {})
        assert result.outcome == "failure"

    async def test_dry_run_does_not_call_regular_publish(self, repo: Path) -> None:
        backend = FakeProcessBackend(responses={("npm", "publish", "--dry-run"): ""})
        host = _make_host(backend, repo_path=str(repo))
        await host.ainvoke("chp.adapters.release.publish_npm", {"dry_run": True})
        assert ("npm", "publish") not in backend.calls


# ---------------------------------------------------------------------------
# SubprocessProcessBackend smoke test
# ---------------------------------------------------------------------------

class TestSubprocessProcessBackend:
    def test_is_instantiable(self) -> None:
        b = SubprocessProcessBackend()
        assert isinstance(b, SubprocessProcessBackend)

    def test_run_invalid_command_raises(self) -> None:
        b = SubprocessProcessBackend()
        with pytest.raises(RuntimeError):
            b.run("git", "--invalid-flag-xyz-does-not-exist", cwd="/tmp")


# ---------------------------------------------------------------------------
# Shaping — discover all 5 capabilities
# ---------------------------------------------------------------------------

class TestShaping:
    def test_five_capabilities_registered(self) -> None:
        adapter = ReleaseAdapter()
        caps = list(adapter.capabilities())
        ids = {c.descriptor.id for c in caps}
        assert "chp.adapters.release.bump" in ids
        assert "chp.adapters.release.sync" in ids
        assert "chp.adapters.release.tag" in ids
        assert "chp.adapters.release.publish_pypi" in ids
        assert "chp.adapters.release.publish_npm" in ids
        assert len(ids) == 5

    def test_medium_risk_for_bump(self) -> None:
        adapter = ReleaseAdapter()
        caps = {c.descriptor.id: c.descriptor for c in adapter.capabilities()}
        assert caps["chp.adapters.release.bump"].risk == "medium"

    def test_high_risk_for_write_capabilities(self) -> None:
        adapter = ReleaseAdapter()
        caps = {c.descriptor.id: c.descriptor for c in adapter.capabilities()}
        for cap_id in (
            "chp.adapters.release.sync",
            "chp.adapters.release.tag",
            "chp.adapters.release.publish_pypi",
            "chp.adapters.release.publish_npm",
        ):
            assert caps[cap_id].risk == "high", f"{cap_id} should be high risk"

    def test_all_schemas_have_additional_properties_false(self) -> None:
        adapter = ReleaseAdapter()
        for cap in adapter.capabilities():
            schema = cap.descriptor.input_schema
            assert schema.get("additionalProperties") is False, (
                f"{cap.descriptor.id} missing additionalProperties: false"
            )

    def test_all_capabilities_have_emits(self) -> None:
        adapter = ReleaseAdapter()
        for cap in adapter.capabilities():
            assert cap.descriptor.emits, f"{cap.descriptor.id} missing emits"
