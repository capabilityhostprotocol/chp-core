"""Tests for service.py (plist/unit generation) and mesh.py manifest I/O."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# service.py — plist generation
# ---------------------------------------------------------------------------

def _make_profile(tmp_path: Path, host_id: str = "test-host") -> Path:
    p = tmp_path / "test-profile.json"
    p.write_text(json.dumps({
        "host_id": host_id,
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": ["http"],
    }))
    return p


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only on macOS")
def test_launchd_no_secrets(tmp_path):
    from chp_host.service import install_service, _launchd_plist_path
    profile_path = _make_profile(tmp_path, "myhost")
    # Redirect plist destination into tmp_path
    import chp_host.service as svc
    orig = svc._launchd_plist_path
    svc._launchd_plist_path = lambda name, system: tmp_path / f"{name}.plist"
    try:
        install_service(str(profile_path), host_id="myhost", unit_name="chp-host-myhost", system=False, secrets=[])
    finally:
        svc._launchd_plist_path = orig
    plist = (tmp_path / "chp-host-myhost.plist").read_text()
    assert "REPLACE_ME" not in plist
    assert "EnvironmentVariables" not in plist
    assert "--secrets-from-keychain" not in plist
    assert "chp_host.cli" in plist
    assert "serve" in plist


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only on macOS")
def test_launchd_with_secrets(tmp_path):
    from chp_host.service import install_service, _launchd_plist_path
    import chp_host.service as svc
    profile_path = _make_profile(tmp_path, "sechost")
    orig = svc._launchd_plist_path
    svc._launchd_plist_path = lambda name, system: tmp_path / f"{name}.plist"
    try:
        install_service(
            str(profile_path),
            host_id="sechost",
            unit_name="chp-host-sechost",
            system=False,
            secrets=["CHP_HOST_API_KEY", "GITHUB_TOKEN"],
        )
    finally:
        svc._launchd_plist_path = orig
    plist = (tmp_path / "chp-host-sechost.plist").read_text()
    assert "REPLACE_ME" not in plist
    assert "EnvironmentVariables" not in plist
    assert "--secrets-from-keychain" in plist
    assert "CHP_HOST_API_KEY" in plist
    assert "GITHUB_TOKEN" in plist


@pytest.mark.skipif(sys.platform != "linux", reason="systemd only on Linux")
def test_systemd_with_secrets(tmp_path):
    from chp_host.service import install_service, _systemd_unit_path
    import chp_host.service as svc
    profile_path = _make_profile(tmp_path, "linuxhost")
    orig = svc._systemd_unit_path
    svc._systemd_unit_path = lambda name, system: tmp_path / f"{name}.service"
    try:
        install_service(
            str(profile_path),
            host_id="linuxhost",
            unit_name="chp-linuxhost",
            system=False,
            secrets=["CHP_HOST_API_KEY"],
        )
    finally:
        svc._systemd_unit_path = orig
    unit = (tmp_path / "chp-linuxhost.service").read_text()
    assert "--secrets-from-keychain CHP_HOST_API_KEY" in unit
    assert "REPLACE_ME" not in unit


def test_build_launchd_plist_no_secrets():
    from chp_host.service import _build_launchd_plist
    content = _build_launchd_plist(
        label="chp.myhost",
        python="/usr/bin/python3",
        profile_path="/tmp/p.json",
        host_id="myhost",
        log_dir="/tmp/logs",
        secrets=[],
    )
    assert "REPLACE_ME" not in content
    assert "EnvironmentVariables" not in content
    assert "--secrets-from-keychain" not in content
    assert "com.chp.chp.myhost" in content


def test_build_launchd_plist_with_secrets():
    from chp_host.service import _build_launchd_plist
    content = _build_launchd_plist(
        label="chp.sechost",
        python="/usr/bin/python3",
        profile_path="/tmp/p.json",
        host_id="sechost",
        log_dir="/tmp/logs",
        secrets=["CHP_HOST_API_KEY", "MY_TOKEN"],
    )
    assert "--secrets-from-keychain" in content
    assert "CHP_HOST_API_KEY" in content
    assert "MY_TOKEN" in content
    assert "REPLACE_ME" not in content


# ---------------------------------------------------------------------------
# mesh.py — manifest I/O
# ---------------------------------------------------------------------------

def test_load_mesh_creates_empty(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    data = mesh_mod.load_mesh()
    assert data["name"] == "mesh"
    assert data["agent_remotes"] == []
    assert "gateway" in data


def test_save_and_reload(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    d = mesh_mod._empty_mesh()
    d["agent_remotes"].append({"url": "http://1.2.3.4:8803", "api_key_env": "KEY0"})
    mesh_mod.save_mesh(d)
    loaded = mesh_mod.load_mesh()
    assert len(loaded["agent_remotes"]) == 1
    assert loaded["agent_remotes"][0]["url"] == "http://1.2.3.4:8803"


def test_next_peer_key_name_empty():
    from chp_host import mesh as mesh_mod
    data = mesh_mod._empty_mesh()
    assert mesh_mod.next_peer_key_name(data) == "CHP_PEER_0_KEY"


def test_next_peer_key_name_increments():
    from chp_host import mesh as mesh_mod
    data = mesh_mod._empty_mesh()
    data["agent_remotes"] = [
        {"url": "http://a:8803", "api_key_env": "CHP_PEER_0_KEY"},
        {"url": "http://b:8803", "api_key_env": "CHP_PEER_1_KEY"},
    ]
    assert mesh_mod.next_peer_key_name(data) == "CHP_PEER_2_KEY"


def test_add_remote_roundtrip(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY", role="worker")
    data = mesh_mod.load_mesh()
    assert len(data["agent_remotes"]) == 1
    r = data["agent_remotes"][0]
    assert r["url"] == "http://10.0.0.1:8803"
    assert r["role"] == "worker"
    assert r["api_key_env"] == "CHP_PEER_0_KEY"
    assert "added" in r


def test_add_remote_duplicate_raises(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY")
    with pytest.raises(ValueError, match="already in mesh"):
        mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_1_KEY")


def test_remove_remote(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY")
    freed = mesh_mod.remove_remote("http://10.0.0.1:8803")
    assert freed == "CHP_PEER_0_KEY"
    data = mesh_mod.load_mesh()
    assert data["agent_remotes"] == []


def test_remove_remote_not_found(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    with pytest.raises(ValueError, match="not found"):
        mesh_mod.remove_remote("http://nonexistent:8803")


def test_find_remote(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY", role="worker")
    assert mesh_mod.find_remote("http://10.0.0.1:8803")["role"] == "worker"
    assert mesh_mod.find_remote("http://nope:8803") is None


def test_mark_verified_stamps_timestamp(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY")
    assert "last_verified" not in mesh_mod.find_remote("http://10.0.0.1:8803")
    mesh_mod.mark_verified("http://10.0.0.1:8803")
    stamped = mesh_mod.find_remote("http://10.0.0.1:8803")
    assert stamped["last_verified"].endswith("Z")


def test_mark_stats_caches_snapshot(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.add_remote("http://10.0.0.1:8803", api_key_env="CHP_PEER_0_KEY")
    mesh_mod.mark_stats("http://10.0.0.1:8803", {"load_per_core": 0.5, "gpu": {"utilization_pct": 12}})
    r = mesh_mod.find_remote("http://10.0.0.1:8803")
    assert r["last_stats"]["load_per_core"] == 0.5
    assert r["last_stats_at"].endswith("Z")


def test_cli_mesh_stats_parses():
    from chp_host.cli import build_parser
    args = build_parser().parse_args(["mesh", "stats"])
    assert args.func.__name__ == "_cmd_mesh_stats"


def test_mark_verified_unknown_url_noop(tmp_path, monkeypatch):
    from chp_host import mesh as mesh_mod
    monkeypatch.setattr(mesh_mod, "mesh_path", lambda: tmp_path / "mesh.json")
    mesh_mod.mark_verified("http://nope:8803")  # must not raise or create entries
    assert mesh_mod.load_mesh()["agent_remotes"] == []


# ---------------------------------------------------------------------------
# cli.py — init/mesh/gateway arg parsing (no execution)
# ---------------------------------------------------------------------------

def test_cli_init_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["init", "--role", "worker", "--yes"])
    assert args.role == "worker"
    assert args.yes is True


def test_specialized_role_profiles_exist():
    from chp_host.cli import _ROLE_PROFILES
    for role in ("inference", "storage", "compute"):
        assert role in _ROLE_PROFILES
        assert _ROLE_PROFILES[role]["adapters"]
    # inference is model-oriented; storage is data-oriented
    assert "vllm" in _ROLE_PROFILES["inference"]["adapters"]
    assert "filesystem" in _ROLE_PROFILES["storage"]["adapters"]


def test_cli_init_accepts_specialized_roles():
    from chp_host.cli import build_parser
    p = build_parser()
    for role in ("inference", "storage", "compute"):
        assert p.parse_args(["init", "--role", role, "--yes"]).role == role


def test_gateway_config_parses_selection(tmp_path):
    from chp_host.environment import EnvironmentConfig
    manifest = tmp_path / "mesh.json"
    manifest.write_text(json.dumps({
        "name": "mesh",
        "agent_remotes": [{"url": "http://x:8803", "api_key_env": "K"}],
        "gateway": {"port": 8800, "selection": "round_robin"},
    }))
    env = EnvironmentConfig.load(str(manifest))
    assert env.gateway.selection == "round_robin"


def test_gateway_config_selection_defaults_first(tmp_path):
    from chp_host.environment import EnvironmentConfig
    manifest = tmp_path / "mesh.json"
    manifest.write_text(json.dumps({
        "name": "mesh",
        "agent_remotes": [{"url": "http://x:8803", "api_key_env": "K"}],
        "gateway": {"port": 8800},
    }))
    env = EnvironmentConfig.load(str(manifest))
    assert env.gateway.selection == "first"


def test_cli_mesh_invite_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["mesh", "invite", "--role", "raspi"])
    assert args.role == "raspi"


def test_cli_mesh_add_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["mesh", "add", "http://1.2.3.4:8803", "--role", "worker"])
    assert args.url == "http://1.2.3.4:8803"
    assert args.role == "worker"


def test_cli_mesh_remove_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["mesh", "remove", "http://1.2.3.4:8803"])
    assert args.url == "http://1.2.3.4:8803"


def test_cli_update_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["update", "--version", "0.8.8", "--channel", "pypi", "--no-restart"])
    assert args.func.__name__ == "_cmd_update"
    assert args.version == "0.8.8"
    assert args.channel == "pypi"
    assert args.restart is False


def test_cli_update_defaults():
    from chp_host.cli import build_parser
    args = build_parser().parse_args(["update"])
    assert args.restart is True
    assert args.channel == "github"
    assert args.version is None


def test_installed_chp_packages_includes_core_and_host():
    from chp_host.cli import _installed_chp_packages
    pkgs = _installed_chp_packages()
    assert "chp-core" in pkgs
    assert "chp-host" in pkgs
    # core + host listed first, no duplicates
    assert pkgs[:2] == ["chp-core", "chp-host"]
    assert len(pkgs) == len(set(pkgs))


def test_chp_host_has_version():
    import chp_host
    assert isinstance(chp_host.__version__, str)
    assert chp_host.__version__


def test_cli_mesh_revoke_parses():
    from chp_host.cli import build_parser
    args = build_parser().parse_args(["mesh", "revoke", "http://1.2.3.4:8803"])
    assert args.url == "http://1.2.3.4:8803"
    assert args.func.__name__ == "_cmd_mesh_revoke"


def test_cli_mesh_rotate_parses():
    from chp_host.cli import build_parser
    args = build_parser().parse_args(["mesh", "rotate", "http://1.2.3.4:8803"])
    assert args.url == "http://1.2.3.4:8803"
    assert args.func.__name__ == "_cmd_mesh_rotate"


def test_cli_gateway_no_env_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["gateway"])
    assert args.environment is None


def test_cli_gateway_with_env_parses():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["gateway", "--environment", "edge-tailscale"])
    assert args.environment == "edge-tailscale"


def test_cli_status_mesh_flag():
    from chp_host.cli import build_parser
    p = build_parser()
    args = p.parse_args(["status", "--mesh"])
    assert args.mesh is True


def test_cli_install_service_secrets():
    from chp_host.cli import build_parser
    p = build_parser()
    profile = "/tmp/fake.json"
    args = p.parse_args(["install-service", "--profile", profile, "--secrets", "KEY1", "KEY2"])
    assert args.secrets == ["KEY1", "KEY2"]


# ---------------------------------------------------------------------------
# cli.py — keychain helpers (§1A: init must reuse an existing key)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="Keychain only on macOS")
def test_read_keychain_roundtrip():
    """_read_keychain returns what _store_keychain wrote (so init can reuse it)."""
    from chp_host.cli import _store_keychain, _read_keychain
    import secrets as _secrets
    name = f"CHP_TEST_{_secrets.token_hex(4)}"
    value = _secrets.token_urlsafe(16)
    try:
        assert _store_keychain(name, value) is True
        assert _read_keychain(name) == value
    finally:
        import subprocess
        subprocess.run(
            ["security", "delete-generic-password", "-a", name, "-s", "com.chp.secrets"],
            capture_output=True,
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Keychain only on macOS")
def test_read_keychain_missing_returns_none():
    from chp_host.cli import _read_keychain
    import secrets as _secrets
    assert _read_keychain(f"CHP_TEST_ABSENT_{_secrets.token_hex(4)}") is None


# ---------------------------------------------------------------------------
# cli.py — adapters --registry (§2C)
# ---------------------------------------------------------------------------

def test_adapters_registry_flag_parses():
    """Parser: chp-host adapters --registry sets args.registry True and routes to _cmd_adapters."""
    from chp_host.cli import build_parser, _cmd_adapters
    args = build_parser().parse_args(["adapters", "--registry"])
    assert args.registry is True
    assert args.func is _cmd_adapters


def test_adapters_no_registry_flag_defaults_false():
    """Parser: chp-host adapters (no --registry) leaves args.registry False."""
    from chp_host.cli import build_parser
    args = build_parser().parse_args(["adapters"])
    assert args.registry is False


_FAKE_REGISTRY = {
    "version": "1",
    "generated": "2026-06-21",
    "official": [
        {
            "id": "chp-adapter-http",
            "category": "network",
            "tier": 1,
            "status": "certified",
            "description": "Governed HTTP client",
        },
        {
            "id": "chp-adapter-filesystem",
            "category": "filesystem",
            "tier": 1,
            "status": "certified",
            "description": "Filesystem read/write",
        },
        {
            "id": "chp-adapter-grpc",
            "category": "network",
            "tier": 2,
            "status": "experimental",
            "description": "gRPC invocation",
        },
    ],
}


def test_adapters_registry_prints_table_and_installed_marker(monkeypatch, capsys):
    """--registry prints a table with INSTALLED marker for locally installed adapters."""
    import io
    import urllib.request as _urlrequest

    fake_json = json.dumps(_FAKE_REGISTRY).encode()

    class _FakeResp:
        def read(self):
            return fake_json
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    monkeypatch.setattr(_urlrequest, "urlopen", lambda req, timeout=10: _FakeResp())

    # Monkeypatch available_adapters to return only "http" as installed.
    import chp_host.cli as cli_mod
    monkeypatch.setattr(cli_mod, "available_adapters", lambda: ["http"])

    from chp_host.cli import build_parser
    args = build_parser().parse_args(["adapters", "--registry"])
    rc = args.func(args)

    assert rc == 0
    out = capsys.readouterr().out

    # Header row present
    assert "NAME" in out
    assert "CATEGORY" in out
    assert "INSTALLED" in out

    # Both registry adapters appear
    assert "chp-adapter-http" in out
    assert "chp-adapter-filesystem" in out
    assert "chp-adapter-grpc" in out

    # Only http is installed (mark present on its row)
    lines = out.splitlines()
    http_line = next(l for l in lines if "chp-adapter-http" in l)
    assert "✓" in http_line, f"Expected ✓ marker for installed adapter, got: {http_line!r}"

    fs_line = next(l for l in lines if "chp-adapter-filesystem" in l)
    assert "✓" not in fs_line, f"filesystem not installed, should have no marker: {fs_line!r}"

    # Summary line
    assert "1/3 registry adapters installed locally." in out


def test_adapters_registry_network_error_returns_1(monkeypatch, capsys):
    """--registry returns exit code 1 and prints a clear error on network failure."""
    import urllib.request as _urlrequest
    import urllib.error

    def _fail(req, timeout=10):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(_urlrequest, "urlopen", _fail)

    import chp_host.cli as cli_mod
    monkeypatch.setattr(cli_mod, "available_adapters", lambda: [])

    from chp_host.cli import build_parser
    args = build_parser().parse_args(["adapters", "--registry"])
    rc = args.func(args)

    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err
