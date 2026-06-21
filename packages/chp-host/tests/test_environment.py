"""Tests for EnvironmentConfig and list_environments."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from chp_host.environment import (
    EnvironmentConfig,
    EnvironmentHostEntry,
    EnvironmentRemoteEntry,
    list_environments,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _minimal_env(name: str = "dev") -> dict:
    return {
        "name": name,
        "description": "Test environment",
        "hosts": [],
        "agent_remotes": ["http://127.0.0.1:8801"],
        "store": ".chp/dev.sqlite",
    }


# ---------------------------------------------------------------------------
# from_dict
# ---------------------------------------------------------------------------

class TestFromDict:
    def test_minimal(self):
        env = EnvironmentConfig.from_dict(_minimal_env())
        assert env.name == "dev"
        # backward compat: string remotes become EnvironmentRemoteEntry
        assert env.agent_remotes == [EnvironmentRemoteEntry(url="http://127.0.0.1:8801")]
        assert env.hosts == []

    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            EnvironmentConfig.from_dict({"hosts": []})

    def test_host_entry_parsed(self):
        data = _minimal_env()
        data["hosts"] = [{"profile": "profiles/dev-host.json", "start_local": True}]
        env = EnvironmentConfig.from_dict(data)
        assert len(env.hosts) == 1
        assert env.hosts[0].profile == "profiles/dev-host.json"
        assert env.hosts[0].start_local is True

    def test_host_entry_start_local_defaults_true(self):
        data = _minimal_env()
        data["hosts"] = [{"profile": "profiles/some.json"}]
        env = EnvironmentConfig.from_dict(data)
        assert env.hosts[0].start_local is True

    def test_host_entry_optional_defaults_false(self):
        data = _minimal_env()
        data["hosts"] = [{"profile": "profiles/some.json"}]
        env = EnvironmentConfig.from_dict(data)
        assert env.hosts[0].optional is False

    def test_host_entry_optional_parsed(self):
        data = _minimal_env()
        data["hosts"] = [{"profile": "profiles/some.json", "optional": True}]
        env = EnvironmentConfig.from_dict(data)
        assert env.hosts[0].optional is True

    def test_store_default_derived_from_name(self):
        data = {"name": "staging", "hosts": []}
        env = EnvironmentConfig.from_dict(data)
        assert "staging" in env.store

    def test_agent_remotes_object_form(self):
        data = _minimal_env()
        data["agent_remotes"] = [
            {"url": "http://127.0.0.1:8801", "optional": False},
            {"url": "http://127.0.0.1:8802", "optional": True},
        ]
        env = EnvironmentConfig.from_dict(data)
        assert env.agent_remotes[0] == EnvironmentRemoteEntry(url="http://127.0.0.1:8801", optional=False)
        assert env.agent_remotes[1] == EnvironmentRemoteEntry(url="http://127.0.0.1:8802", optional=True)

    def test_agent_remotes_mixed_backward_compat(self):
        data = _minimal_env()
        data["agent_remotes"] = [
            "http://127.0.0.1:8801",
            {"url": "http://127.0.0.1:8802", "optional": True},
        ]
        env = EnvironmentConfig.from_dict(data)
        assert env.agent_remotes[0] == EnvironmentRemoteEntry(url="http://127.0.0.1:8801", optional=False)
        assert env.agent_remotes[1] == EnvironmentRemoteEntry(url="http://127.0.0.1:8802", optional=True)


# ---------------------------------------------------------------------------
# load
# ---------------------------------------------------------------------------

class TestLoad:
    def test_load_by_path(self, tmp_path):
        env_file = tmp_path / "dev.json"
        _write_json(env_file, _minimal_env("dev"))
        env = EnvironmentConfig.load(str(env_file))
        assert env.name == "dev"

    def test_load_by_name(self, tmp_path):
        envs_dir = tmp_path / "environments"
        envs_dir.mkdir()
        _write_json(envs_dir / "staging.json", _minimal_env("staging"))
        env = EnvironmentConfig.load("staging", base_dir=str(tmp_path))
        assert env.name == "staging"

    def test_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            EnvironmentConfig.load("nonexistent", base_dir=str(tmp_path))

    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("[1, 2, 3]")
        with pytest.raises(ValueError, match="JSON object"):
            EnvironmentConfig.load(str(bad))


# ---------------------------------------------------------------------------
# resolve_remotes
# ---------------------------------------------------------------------------

class TestResolveRemotes:
    def test_static_urls_unchanged(self):
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "agent_remotes": ["http://127.0.0.1:8801", "http://127.0.0.1:8802"],
        })
        remotes = env.resolve_remotes()
        assert [r.url for r in remotes] == ["http://127.0.0.1:8801", "http://127.0.0.1:8802"]

    def test_var_expansion(self):
        os.environ["_TEST_HOST_URL"] = "https://prod.example.com"
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "agent_remotes": ["${_TEST_HOST_URL}"],
        })
        remotes = env.resolve_remotes()
        assert remotes[0].url == "https://prod.example.com"
        del os.environ["_TEST_HOST_URL"]

    def test_unset_var_kept_as_is(self):
        os.environ.pop("_UNSET_VAR_XYZ", None)
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "agent_remotes": ["${_UNSET_VAR_XYZ}"],
        })
        remotes = env.resolve_remotes()
        assert remotes[0].url == "${_UNSET_VAR_XYZ}"

    def test_partial_expansion(self):
        os.environ["_TEST_PORT"] = "9000"
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "agent_remotes": ["http://localhost:${_TEST_PORT}"],
        })
        remotes = env.resolve_remotes()
        assert remotes[0].url == "http://localhost:9000"
        del os.environ["_TEST_PORT"]

    def test_optional_flag_preserved(self):
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "agent_remotes": [
                {"url": "http://127.0.0.1:8801", "optional": False},
                {"url": "http://127.0.0.1:8802", "optional": True},
            ],
        })
        remotes = env.resolve_remotes()
        assert remotes[0].optional is False
        assert remotes[1].optional is True

    def test_returns_environment_remote_entry_list(self):
        env = EnvironmentConfig.from_dict(_minimal_env())
        remotes = env.resolve_remotes()
        assert all(isinstance(r, EnvironmentRemoteEntry) for r in remotes)


# ---------------------------------------------------------------------------
# EnvironmentHostEntry optional
# ---------------------------------------------------------------------------

class TestEnvironmentHostEntryOptional:
    def test_optional_false_default(self):
        entry = EnvironmentHostEntry(profile="profiles/some.json")
        assert entry.optional is False

    def test_optional_true(self):
        entry = EnvironmentHostEntry(profile="profiles/some.json", optional=True)
        assert entry.optional is True

    def test_missing_optional_profile_skips_with_warning(self, tmp_path):
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/nonexistent.json", "optional": True, "start_local": True}],
        })
        with pytest.warns(UserWarning, match="Optional host profile"):
            profiles = env.host_profiles(base_dir=str(tmp_path))
        assert profiles == []

    def test_missing_required_profile_raises(self, tmp_path):
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/nonexistent.json", "optional": False, "start_local": True}],
        })
        with pytest.raises((OSError, FileNotFoundError)):
            env.host_profiles(base_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# host_profiles_with_entries
# ---------------------------------------------------------------------------

class TestHostProfilesWithEntries:
    def test_returns_profile_and_entry_tuples(self, tmp_path):
        profile_data = {
            "host_id": "dev-host",
            "adapters": ["git"],
            "bind": "127.0.0.1",
            "port": 8801,
        }
        _write_json(tmp_path / "profiles" / "dev-host.json", profile_data)
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/dev-host.json", "start_local": True, "optional": False}],
        })
        pairs = env.host_profiles_with_entries(base_dir=str(tmp_path))
        assert len(pairs) == 1
        profile, entry = pairs[0]
        assert profile.host_id == "dev-host"
        assert entry.optional is False

    def test_optional_entry_accessible(self, tmp_path):
        profile_data = {
            "host_id": "cloud-host",
            "adapters": ["github"],
            "bind": "127.0.0.1",
            "port": 8802,
        }
        _write_json(tmp_path / "profiles" / "cloud-host.json", profile_data)
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/cloud-host.json", "start_local": True, "optional": True}],
        })
        pairs = env.host_profiles_with_entries(base_dir=str(tmp_path))
        assert len(pairs) == 1
        _, entry = pairs[0]
        assert entry.optional is True


# ---------------------------------------------------------------------------
# host_profiles
# ---------------------------------------------------------------------------

class TestHostProfiles:
    def test_no_local_hosts_returns_empty(self):
        env = EnvironmentConfig.from_dict(_minimal_env())
        profiles = env.host_profiles(base_dir=".")
        assert profiles == []

    def test_start_local_false_skipped(self, tmp_path):
        profile_data = {
            "host_id": "remote-host",
            "adapters": ["git"],
            "bind": "0.0.0.0",
            "port": 8803,
        }
        _write_json(tmp_path / "profiles" / "remote.json", profile_data)
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/remote.json", "start_local": False}],
        })
        profiles = env.host_profiles(base_dir=str(tmp_path))
        assert profiles == []

    def test_local_profile_loaded(self, tmp_path):
        profile_data = {
            "host_id": "dev-host",
            "adapters": ["git"],
            "bind": "127.0.0.1",
            "port": 8801,
        }
        _write_json(tmp_path / "profiles" / "dev-host.json", profile_data)
        env = EnvironmentConfig.from_dict({
            **_minimal_env(),
            "hosts": [{"profile": "profiles/dev-host.json", "start_local": True}],
        })
        profiles = env.host_profiles(base_dir=str(tmp_path))
        assert len(profiles) == 1
        assert profiles[0].host_id == "dev-host"
        assert profiles[0].adapters == ["git"]


# ---------------------------------------------------------------------------
# list_environments
# ---------------------------------------------------------------------------

class TestListEnvironments:
    def test_empty_dir_returns_empty(self, tmp_path):
        (tmp_path / "environments").mkdir()
        assert list_environments(str(tmp_path / "environments")) == []

    def test_missing_dir_returns_empty(self, tmp_path):
        assert list_environments(str(tmp_path / "nonexistent")) == []

    def test_lists_json_stems_sorted(self, tmp_path):
        envs = tmp_path / "environments"
        envs.mkdir()
        (envs / "prod.json").write_text("{}")
        (envs / "dev.json").write_text("{}")
        (envs / "staging.json").write_text("{}")
        names = list_environments(str(envs))
        assert names == ["dev", "prod", "staging"]

    def test_ignores_non_json(self, tmp_path):
        envs = tmp_path / "environments"
        envs.mkdir()
        (envs / "dev.json").write_text("{}")
        (envs / "notes.txt").write_text("ignore me")
        names = list_environments(str(envs))
        assert names == ["dev"]


# ---------------------------------------------------------------------------
# GatewayConfig parsing
# ---------------------------------------------------------------------------

class TestGatewayConfig:
    def _env(self, extra: dict = {}) -> dict:
        return {"name": "test", **extra}

    def test_gateway_absent_is_none(self):
        from chp_host import EnvironmentConfig
        env = EnvironmentConfig.from_dict(self._env())
        assert env.gateway is None

    def test_gateway_section_parsed(self):
        from chp_host import EnvironmentConfig, GatewayConfig
        env = EnvironmentConfig.from_dict(self._env({
            "gateway": {"port": 9900, "bind": "127.0.0.1", "host_id": "my-gw"}
        }))
        assert isinstance(env.gateway, GatewayConfig)
        assert env.gateway.port == 9900
        assert env.gateway.bind == "127.0.0.1"
        assert env.gateway.host_id == "my-gw"

    def test_gateway_defaults(self):
        from chp_host import EnvironmentConfig, GatewayConfig
        env = EnvironmentConfig.from_dict(self._env({"gateway": {}}))
        assert isinstance(env.gateway, GatewayConfig)
        assert env.gateway.port == 8800
        assert env.gateway.bind == "0.0.0.0"
        assert env.gateway.host_id == "chp-gateway"

    def test_gateway_non_dict_is_none(self):
        from chp_host import EnvironmentConfig
        # A non-dict gateway value (e.g. string) is treated as absent.
        env = EnvironmentConfig.from_dict(self._env({"gateway": "invalid"}))
        assert env.gateway is None
