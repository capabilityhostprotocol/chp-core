"""chp-host CLI — serve a real adapter host, or list available adapters.

    chp-host serve --adapters aws,azure,gcp,kubernetes --port 8801
    chp-host serve --profile cloud.json
    chp-host serve --environment dev
    chp-host mcp --adapters git,github,planning,delegation,safety
    chp-host mcp --profile my-profile.json
    chp-host init [--role primary|worker|raspi|linux-worker]
    chp-host mesh invite|add|list|remove
    chp-host gateway          (defaults to ~/.chp/mesh.json)
    chp-host adapters
    chp-host environments
    chp-host status [--environment NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import secrets as _secrets_mod
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

from chp_core.http import serve_http

from .environment import EnvironmentConfig, list_environments
from .profile import HostProfile
from .serve import available_adapters, build_adapter_host


def _inject_keychain_secrets(keys: list[str]) -> None:
    """Read each key from macOS Keychain (com.chp.secrets) and set in os.environ."""
    import subprocess
    _SVC = "com.chp.secrets"
    injected, missing = [], []
    for key in keys:
        r = subprocess.run(
            ["security", "find-generic-password", "-a", key, "-s", _SVC, "-w"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            os.environ[key] = r.stdout.strip()
            injected.append(key)
        else:
            missing.append(key)
    if injected:
        print(f"Keychain: injected {', '.join(injected)}", file=sys.stderr)
    if missing:
        print(f"Keychain: WARNING — not found: {', '.join(missing)}", file=sys.stderr)


def _cmd_serve(args: argparse.Namespace) -> int:
    if getattr(args, "secrets_from_keychain", None):
        _inject_keychain_secrets(args.secrets_from_keychain)
    # Environment mode: start all local hosts defined in the manifest concurrently.
    env_name = args.environment or os.environ.get("CHP_ENVIRONMENT")
    if env_name:
        base_dir = args.env_dir or os.getcwd()
        try:
            env = EnvironmentConfig.load(env_name, base_dir=base_dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: cannot load environment {env_name!r}: {exc}", file=sys.stderr)
            return 1
        profile_entries = env.host_profiles_with_entries(base_dir=base_dir)
        if not profile_entries:
            print(f"ERROR: environment {env_name!r} defines no local hosts to start.", file=sys.stderr)
            return 1
        print(f"CHP environment {env_name!r} — starting {len(profile_entries)} host(s):")
        threads = []
        for profile, entry in profile_entries:
            host, result = build_adapter_host(
                profile.adapters, host_id=profile.host_id, store_path=profile.store
            )
            cap_count = len(host.discover().get("capabilities", []))
            tag = "[optional]" if entry.optional else "[required]"
            if cap_count == 0 and entry.optional:
                print(f"  {profile.host_id!r} — 0 capabilities (no credentials?), skipping {tag}")
                continue
            print(f"  {profile.host_id!r} — {cap_count} capabilities at http://{profile.bind}:{profile.port} {tag}")
            print(result.summary() or "  (none)")
            t = threading.Thread(
                target=serve_http,
                args=(host,),
                kwargs={"bind": profile.bind, "port": profile.port},
                daemon=False,
            )
            threads.append(t)
        if not threads:
            print("No hosts to start (all optional hosts had 0 capabilities).", file=sys.stderr)
            return 1
        for t in threads:
            t.start()
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("\nStopped CHP environment hosts.")
        return 0

    # Profile mode
    if args.profile:
        try:
            profile = HostProfile.load(args.profile)
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot load profile {args.profile!r}: {exc}", file=sys.stderr)
            return 1
        if profile.secrets:
            _inject_keychain_secrets(profile.secrets)
        adapters = profile.adapters
        host_id = profile.host_id
        bind, port, store = profile.bind, profile.port, profile.store
    else:
        if not args.adapters:
            print("ERROR: provide --adapters a,b,c or --profile FILE or --environment NAME", file=sys.stderr)
            return 1
        adapters = [a.strip() for a in args.adapters.split(",") if a.strip()]
        host_id = args.host_id
        bind, port, store = args.bind, args.port, args.store

    host, result = build_adapter_host(adapters, host_id=host_id, store_path=store)
    print(f"CHP host {host_id!r} — adapter registration:")
    print(result.summary() or "  (none)")
    cap_count = len(host.discover().get("capabilities", []))
    print(f"\nServing {cap_count} capabilities at http://{bind}:{port}")
    print("Routes: GET /health, GET /host, GET /capabilities, POST /invoke, GET /replay/{id}, GET /verify/{id}")
    try:
        serve_http(host, bind=bind, port=port)
    except KeyboardInterrupt:
        print("\nStopped CHP host.")
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    """Start an MCP stdio server exposing CHP adapter capabilities as tools."""
    if getattr(args, "secrets_from_keychain", None):
        _inject_keychain_secrets(args.secrets_from_keychain)
    try:
        from .mcp_server import run_mcp_server
    except ImportError as exc:
        print(f"ERROR: MCP support requires 'mcp' package: {exc}", file=sys.stderr)
        print("Install it with: pip install 'mcp>=1.0'", file=sys.stderr)
        return 1

    # Environment mode — route through MultiHostRouter over HTTP transports.
    env_name = getattr(args, "environment", None) or os.environ.get("CHP_ENVIRONMENT")
    if env_name:
        from chp_core.transport import HttpTransport, LocalTransport
        from .router import MultiHostRouter

        base_dir = getattr(args, "env_dir", None) or os.getcwd()
        try:
            env = EnvironmentConfig.load(env_name, base_dir=base_dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: cannot load environment {env_name!r}: {exc}", file=sys.stderr)
            return 1

        transports: list = []

        # Local hosts defined in the manifest (start_local=True).
        for profile, entry in env.host_profiles_with_entries(base_dir=base_dir):
            local_host, _ = build_adapter_host(
                profile.adapters, host_id=profile.host_id, store_path=profile.store
            )
            transports.append(LocalTransport(local_host, name=profile.host_id))

        # Remote HTTP hosts from agent_remotes.
        for remote in env.resolve_remotes():
            transports.append(HttpTransport(
                remote.url, name=remote.url, api_key=remote.api_key,
            ))

        if not transports:
            print("ERROR: environment defines no hosts (no local profiles and no agent_remotes)", file=sys.stderr)
            return 1

        router = MultiHostRouter(transports)
        print(f"chp-host mcp: environment {env_name!r} — {len(transports)} transport(s)", file=sys.stderr)
        asyncio.run(run_mcp_server(router, server_name=args.host_id, min_status=args.min_status))
        return 0

    if args.profile:
        try:
            profile = HostProfile.load(args.profile)
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot load profile {args.profile!r}: {exc}", file=sys.stderr)
            return 1
        adapters = profile.adapters
        host_id = profile.host_id
        store = profile.store
    else:
        if not args.adapters:
            print("ERROR: provide --adapters a,b,c or --profile FILE", file=sys.stderr)
            return 1
        adapters = [a.strip() for a in args.adapters.split(",") if a.strip()]
        host_id = args.host_id
        store = args.store

    host, result = build_adapter_host(adapters, host_id=host_id, store_path=store)
    cap_count = len(host.discover().get("capabilities", []))
    print(f"chp-host mcp: {host_id!r} — {cap_count} tools", file=sys.stderr)
    if result.skipped:
        for name, reason in result.skipped.items():
            print(f"  skipped {name}: {reason}", file=sys.stderr)

    asyncio.run(run_mcp_server(host, server_name=host_id, min_status=args.min_status))
    return 0


_REGISTRY_URL = (
    "https://raw.githubusercontent.com/capabilityhostprotocol/chp-core"
    "/main/registry/adapters.json"
)
_ADAPTER_ID_PREFIX = "chp-adapter-"


def _cmd_adapters(args: argparse.Namespace) -> int:
    names = available_adapters()

    if getattr(args, "registry", False):
        # Fetch public registry and compare against installed adapters.
        try:
            req = urllib.request.Request(
                _REGISTRY_URL,
                headers={"User-Agent": "chp-host/adapters-registry"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                registry = json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            print(f"ERROR: could not fetch registry: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"ERROR: unexpected error fetching registry: {exc}", file=sys.stderr)
            return 1

        official = registry.get("official", [])
        if not official:
            print("Registry returned no official adapters.", file=sys.stderr)
            return 1

        # Normalize hyphen/underscore: registry ids use hyphens
        # (chp-adapter-local-llm), entry-point names use underscores (local_llm).
        def _norm(n: str) -> str:
            return n.replace("-", "_")

        installed_set = {_norm(n) for n in names}  # short names like "http", "local_llm"

        # Group by category then sort by name within each group.
        by_category: dict[str, list[dict]] = {}
        for entry in official:
            cat = entry.get("category", "other")
            by_category.setdefault(cat, []).append(entry)
        for cat in by_category:
            by_category[cat].sort(key=lambda e: e.get("id", ""))

        name_w, cat_w, tier_w, status_w = 36, 14, 6, 14
        header = (
            f"{'NAME':<{name_w}} {'CATEGORY':<{cat_w}} {'TIER':<{tier_w}}"
            f" {'STATUS':<{status_w}} INSTALLED"
        )
        print(header)
        print("-" * len(header))

        for cat in sorted(by_category.keys()):
            for entry in by_category[cat]:
                adapter_id = entry.get("id", "")
                short_name = (
                    adapter_id[len(_ADAPTER_ID_PREFIX):]
                    if adapter_id.startswith(_ADAPTER_ID_PREFIX)
                    else adapter_id
                )
                tier = entry.get("tier", "-")
                status = entry.get("status", "-")
                installed_marker = "✓" if _norm(short_name) in installed_set else ""
                print(
                    f"{adapter_id:<{name_w}} {cat:<{cat_w}} {tier!s:<{tier_w}}"
                    f" {status:<{status_w}} {installed_marker}"
                )

        installed_count = sum(
            1 for e in official
            if _norm(e.get("id", "")[len(_ADAPTER_ID_PREFIX):]
                     if e.get("id", "").startswith(_ADAPTER_ID_PREFIX)
                     else e.get("id", "")) in installed_set
        )
        print(f"\n{installed_count}/{len(official)} registry adapters installed locally.")
        return 0

    # Default: list installed adapters.
    if not names:
        print("No chp.adapters entry points installed.")
        return 0
    print(f"{len(names)} installed adapters:")
    for name in names:
        print(f"  {name}")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Show status of running CHP hosts by scanning .chp/*.pid files."""
    base_dir = args.env_dir or os.getcwd()
    chp_dir = os.path.join(base_dir, ".chp")

    # Collect (host_id, port, optional) from env manifest if given
    env_info: dict[str, dict] = {}
    env_name = args.environment or os.environ.get("CHP_ENVIRONMENT")
    if env_name:
        try:
            env = EnvironmentConfig.load(env_name, base_dir=base_dir)
            profile_entries = env.host_profiles_with_entries(base_dir=base_dir)
            for profile, entry in profile_entries:
                env_info[profile.host_id] = {
                    "port": profile.port,
                    "bind": profile.bind,
                    "optional": entry.optional,
                }
        except (FileNotFoundError, ValueError) as exc:
            print(f"Warning: cannot load environment {env_name!r}: {exc}", file=sys.stderr)

    # Scan PID files
    if not os.path.isdir(chp_dir):
        print("No .chp/ directory found — no hosts have been started.")
        return 0

    pid_files = sorted(f for f in os.listdir(chp_dir) if f.endswith(".pid"))
    if not pid_files and not env_info:
        print("No PID files found in .chp/.")
        return 0

    print("CHP Host Status:")
    rows = []

    # Build rows from PID files
    seen_host_ids: set[str] = set()
    for fname in pid_files:
        host_id = fname[:-4]  # strip .pid
        seen_host_ids.add(host_id)
        pid_path = os.path.join(chp_dir, fname)
        try:
            pid = int(open(pid_path).read().strip())
        except (OSError, ValueError):
            pid = None

        running = False
        if pid:
            try:
                os.kill(pid, 0)
                running = True
            except OSError:
                pass

        # Lookup port from env_info or try to infer from log file
        info = env_info.get(host_id, {})
        port = info.get("port")
        bind = info.get("bind", "127.0.0.1")
        optional = info.get("optional", False)
        tag = "[optional]" if optional else "[required]"

        # Try health check if we know the port
        health_ok = False
        if running and port:
            try:
                urllib.request.urlopen(
                    f"http://{bind}:{port}/health", timeout=1
                )
                health_ok = True
            except (urllib.error.URLError, OSError):
                pass

        status = "UP" if (running and health_ok) else ("PROC" if running else "DOWN")
        pid_str = f"(pid {pid})" if pid else ""
        port_str = f":{port}" if port else ""
        rows.append(f"  {host_id:<20} {port_str:<6}  {status:<5} {pid_str:<12}  {tag}")

    # Add env manifest entries not found in PID files
    for host_id, info in env_info.items():
        if host_id in seen_host_ids:
            continue
        port = info.get("port")
        optional = info.get("optional", False)
        tag = "[optional]" if optional else "[required]"
        port_str = f":{port}" if port else ""
        rows.append(f"  {host_id:<20} {port_str:<6}  {'DOWN':<5} {'':12}  {tag}")

    for row in rows:
        print(row)

    # Show mesh remotes from ~/.chp/mesh.json
    if getattr(args, "mesh", False) or not rows:
        from .mesh import load_mesh, mesh_path
        data = load_mesh()
        remotes = data.get("agent_remotes") or []
        if remotes:
            print("\nMesh remotes:")
            for r in remotes:
                url = r.get("url", "")
                role = r.get("role", "?")
                try:
                    resp = urllib.request.urlopen(f"{url}/health", timeout=2)
                    h = json.loads(resp.read().decode())
                    caps = h.get("capability_count", "?")
                    status = "UP"
                except Exception:
                    caps = "-"
                    status = "DOWN"
                print(f"  {url:<36} {role:<10}  {status:<5} {caps} caps")

    return 0


def _cmd_install_service(args: argparse.Namespace) -> int:
    from .service import install_service

    if not args.profile:
        print("ERROR: --profile FILE is required", file=sys.stderr)
        return 1
    try:
        profile = HostProfile.load(args.profile)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot load profile {args.profile!r}: {exc}", file=sys.stderr)
        return 1

    unit_name = args.unit_name or f"chp-host-{profile.host_id}"
    secrets = getattr(args, "secrets", None) or profile.secrets or []
    try:
        install_service(
            profile_path=args.profile,
            host_id=profile.host_id,
            unit_name=unit_name,
            system=args.system,
            user=args.user or None,
            secrets=secrets,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_uninstall_service(args: argparse.Namespace) -> int:
    from .service import uninstall_service

    if not args.unit_name:
        print("ERROR: --unit-name NAME is required", file=sys.stderr)
        return 1
    try:
        uninstall_service(unit_name=args.unit_name, system=args.system)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_gateway(args: argparse.Namespace) -> int:
    """Start a CHP HTTP gateway that routes across all transports in an environment."""
    from chp_core.transport import HttpTransport, LocalTransport
    from .router import MultiHostRouter

    keychain_keys = getattr(args, "secrets_from_keychain", None) or []
    if keychain_keys:
        _inject_keychain_secrets(keychain_keys)

    env_name = getattr(args, "environment", None) or os.environ.get("CHP_ENVIRONMENT")
    base_dir = getattr(args, "env_dir", None) or os.getcwd()

    # Default: load ~/.chp/mesh.json when no environment specified
    if not env_name:
        from .mesh import mesh_path
        default_mesh = mesh_path()
        if default_mesh.exists():
            print(f"CHP gateway: loading default mesh manifest {default_mesh}")
            try:
                env = EnvironmentConfig.load(str(default_mesh))
            except (FileNotFoundError, ValueError) as exc:
                print(f"ERROR: cannot load mesh manifest: {exc}", file=sys.stderr)
                return 1
        else:
            print(
                "ERROR: --environment NAME is required (or create ~/.chp/mesh.json with "
                "'chp-host mesh add' / 'chp-host init')",
                file=sys.stderr,
            )
            return 1
    else:
        try:
            env = EnvironmentConfig.load(env_name, base_dir=base_dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: cannot load environment {env_name!r}: {exc}", file=sys.stderr)
            return 1

    gw = env.gateway
    bind = getattr(args, "bind", None) or (gw.bind if gw else "0.0.0.0")
    port = getattr(args, "port", None) or (gw.port if gw else 8800)
    host_id = getattr(args, "host_id", None) or (gw.host_id if gw else "chp-gateway")

    transports: list = []

    # Local hosts defined in the manifest (start_local=True).
    for profile, _ in env.host_profiles_with_entries(base_dir=base_dir):
        local_host, _ = build_adapter_host(
            profile.adapters, host_id=profile.host_id, store_path=profile.store
        )
        transports.append(LocalTransport(local_host, name=profile.host_id))

    # Remote HTTP hosts from agent_remotes.
    for remote in env.resolve_remotes():
        transports.append(HttpTransport(
            remote.url, name=remote.url, api_key=remote.api_key,
        ))

    if not transports:
        print(
            "ERROR: environment defines no transports (no local profiles and no agent_remotes)",
            file=sys.stderr,
        )
        return 1

    selection = (gw.selection if gw else None) or "first"
    router = MultiHostRouter(transports, selection=selection, host_id=host_id)
    print(f"CHP gateway {host_id!r} — connecting to {len(transports)} transport(s) "
          f"(selection={selection})...")
    asyncio.run(router.connect())

    cap_count = len(router.capability_ids)
    print(f"Routing table: {cap_count} capabilities across {len(router._descriptors)} host(s)")
    for cap_id in router.capability_ids[:10]:
        owners = router.hosts_for(cap_id)
        print(f"  {cap_id} -> {owners}")
    if cap_count > 10:
        print(f"  ... and {cap_count - 10} more")

    print(f"\nServing at http://{bind}:{port}")
    print("Routes: GET /health  GET /host  GET /capabilities  POST /invoke  GET /replay/{{id}}")
    try:
        serve_http(router, bind=bind, port=port)
    except KeyboardInterrupt:
        print("\nStopped CHP gateway.")
    return 0


def _cmd_secrets(args: argparse.Namespace) -> int:
    """Manage CHP secrets in the macOS Keychain (service: com.chp.secrets)."""
    import platform
    if platform.system() != "Darwin":
        print("ERROR: secrets keychain backend requires macOS", file=sys.stderr)
        return 1

    try:
        from chp_adapter_secrets.backends import KeychainBackend
    except ImportError:
        print("ERROR: chp-adapter-secrets not installed", file=sys.stderr)
        return 1

    backend = KeychainBackend()
    action = args.secrets_action

    if action == "set":
        import getpass
        key = args.key
        if getattr(args, "stdin", False):
            value = sys.stdin.readline().rstrip("\n")
        else:
            value = getpass.getpass(f"Value for {key!r}: ")
        backend.set(key, value)
        print(f"Stored {key!r} in Keychain (service: com.chp.secrets)")
        return 0

    if action == "get":
        value = backend.get(args.key)
        if value is None:
            print(f"ERROR: {args.key!r} not found in Keychain", file=sys.stderr)
            return 1
        print(value)
        return 0

    if action == "delete":
        deleted = backend.delete(args.key)
        if deleted:
            print(f"Deleted {args.key!r} from Keychain")
        else:
            print(f"{args.key!r} not found in Keychain")
        return 0

    if action == "list":
        keys = backend.list_keys()
        if not keys:
            print("No secrets in Keychain index (com.chp.secrets).")
        else:
            print(f"{len(keys)} secret(s):")
            for k in keys:
                print(f"  {k}")
        return 0

    return 1


def _cmd_environments(args: argparse.Namespace) -> int:
    env_dir = args.env_dir or os.path.join(os.getcwd(), "environments")
    names = list_environments(env_dir)
    if not names:
        print(f"No environments found in {env_dir!r}.")
        return 0
    print(f"{len(names)} environment(s) in {env_dir!r}:")
    for name in names:
        print(f"  {name}")
    return 0


# ---------------------------------------------------------------------------
# Role definitions for init
# ---------------------------------------------------------------------------

_ROLE_PROFILES = {
    "primary": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": [
            "git", "github", "planning", "delegation", "safety", "local_llm",
            "radicle", "secrets", "filesystem", "messages", "composition",
            "conformance", "ci", "huggingface", "http", "tei", "vllm",
            "smolagents", "launchd", "jobs", "audit", "scout", "tailscale",
        ],
    },
    "worker": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": [
            "http", "filesystem", "process", "audit", "tailscale", "local_llm", "jobs",
        ],
    },
    # Specialized worker roles for distributing capabilities across the mesh:
    # an inference node runs models, a storage node holds data, a compute node
    # runs jobs/processes. Each still carries audit + tailscale for evidence and
    # mesh reachability.
    "inference": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": [
            "local_llm", "vllm", "tei", "huggingface",
            "filesystem", "audit", "tailscale",
        ],
    },
    "storage": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": ["filesystem", "jobs", "audit", "tailscale"],
    },
    "compute": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": ["process", "jobs", "http", "filesystem", "audit", "tailscale"],
    },
    "raspi": {
        "bind": "0.0.0.0",
        "port": 8801,
        "adapters": ["http", "filesystem", "process", "audit", "jobs"],
    },
    "linux-worker": {
        "bind": "0.0.0.0",
        "port": 8803,
        "adapters": ["http", "filesystem", "process", "audit", "jobs"],
    },
}


def _detect_role() -> str:
    if sys.platform == "darwin":
        return "primary"
    if sys.platform == "linux":
        if platform.machine().lower() in ("aarch64", "arm64"):
            return "raspi"
        return "linux-worker"
    return "worker"


def _tailscale_ip() -> str:
    try:
        r = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return r.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return ""


def _store_keychain(key: str, value: str) -> bool:
    try:
        r = subprocess.run(
            ["security", "add-generic-password", "-a", key,
             "-s", "com.chp.secrets", "-w", value, "-U"],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    except Exception:
        return False


def _read_keychain(key: str) -> str | None:
    """Return the value stored under *key* in the CHP keychain, or None."""
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-a", key,
             "-s", "com.chp.secrets", "-w"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _delete_keychain(key: str) -> bool:
    """Delete *key* from the CHP keychain. Returns True if it was removed."""
    try:
        r = subprocess.run(
            ["security", "delete-generic-password", "-a", key, "-s", "com.chp.secrets"],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    except Exception:
        return False


def _health_poll(url: str, retries: int = 10, delay: float = 1.0) -> bool:
    for _ in range(retries):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# chp-host init
# ---------------------------------------------------------------------------

def _cmd_init(args: argparse.Namespace) -> int:
    role = getattr(args, "role", None)
    yes = getattr(args, "yes", False)
    port_override = getattr(args, "port", None)

    if not role:
        role = _detect_role()

    if not yes:
        print(f"Detected role: {role!r}")
        ans = input(f"  Confirm role [{role}]: ").strip()
        if ans:
            role = ans

    rdef = _ROLE_PROFILES.get(role)
    if rdef is None:
        print(f"ERROR: unknown role {role!r}. Choose: {', '.join(_ROLE_PROFILES)}", file=sys.stderr)
        return 1

    host_id = f"chp-{role.replace('_', '-')}"
    port = port_override or rdef["port"]
    chp_dir = Path.home() / ".chp"
    config_dir = chp_dir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)

    profile_path = config_dir / f"{role}.json"
    profile_data = {
        "host_id": host_id,
        "bind": rdef["bind"],
        "port": port,
        "store": str(chp_dir / f"{host_id}.sqlite"),
        "secrets": ["CHP_HOST_API_KEY"],
        "adapters": rdef["adapters"],
    }
    profile_path.write_text(json.dumps(profile_data, indent=2) + "\n")
    print(f"  Profile: {profile_path}")

    # API key: reuse an existing one if present, otherwise generate + store.
    # The mesh invite flow has the operator pre-seed CHP_HOST_API_KEY (via
    # `chp-host secrets set` or the env file) with the key the primary already
    # holds as CHP_PEER_n_KEY. Regenerating here would break that match and the
    # primary's `mesh add` would 401 — so an existing key always wins.
    if sys.platform == "darwin":
        existing = _read_keychain("CHP_HOST_API_KEY")
        if existing:
            api_key = existing
            print("  Using existing CHP_HOST_API_KEY from Keychain")
        else:
            api_key = _secrets_mod.token_urlsafe(32)
            if _store_keychain("CHP_HOST_API_KEY", api_key):
                print("  API key generated and stored in Keychain (CHP_HOST_API_KEY)")
            else:
                print("  WARNING: could not store in Keychain. Set manually:")
                print("    chp-host secrets set CHP_HOST_API_KEY")
    else:
        env_file = chp_dir / f"{host_id}.env"
        existing = os.environ.get("CHP_HOST_API_KEY")
        if not existing and env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("CHP_HOST_API_KEY="):
                    existing = line.split("=", 1)[1].strip()
                    break
        if existing:
            api_key = existing
            print("  Using existing CHP_HOST_API_KEY")
        else:
            api_key = _secrets_mod.token_urlsafe(32)
            env_file.write_text(f"CHP_HOST_API_KEY={api_key}\n")
            print(f"  API key generated and written to {env_file} (mode 600)")
            try:
                env_file.chmod(0o600)
            except Exception:
                pass

    # Install service
    from .service import install_service
    unit_name = f"chp-host-{host_id}"
    install_service(
        profile_path=str(profile_path),
        host_id=host_id,
        unit_name=unit_name,
        system=False,
        secrets=["CHP_HOST_API_KEY"],
    )

    # Auto-load on macOS
    if sys.platform == "darwin":
        from .service import _launchd_plist_path
        plist = _launchd_plist_path(unit_name, system=False)
        r = subprocess.run(["launchctl", "load", str(plist)], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  Service loaded: launchctl load {plist}")
        else:
            print(f"  WARNING: launchctl load failed: {r.stderr.strip()}")
            print(f"  Run manually: launchctl load {plist}")
    else:
        scope = "--user"
        print(f"\n  To start:")
        print(f"    systemctl {scope} daemon-reload && systemctl {scope} enable {unit_name} && systemctl {scope} start {unit_name}")

    # For primary on macOS, also install gateway service
    if role == "primary" and sys.platform == "darwin":
        _install_gateway_service(chp_dir, yes=yes)

    # Health check
    health_url = f"http://127.0.0.1:{port}/health"
    print(f"\n  Waiting for host at {health_url} ...")
    if _health_poll(health_url):
        print(f"  ✓ CHP host {host_id!r} is up")
    else:
        print(f"  Service may need a moment — check: curl {health_url}")

    # Join snippet
    ts_ip = _tailscale_ip()
    print(f"\n  API key: {api_key}")
    print(f"    (Store this on the PRIMARY machine when joining the mesh.)")
    print(f"\n  To add this node to your primary's mesh:")
    print(f"    On PRIMARY: chp-host mesh add http://<this-ip>:{port}")
    if ts_ip:
        print(f"    Tailscale:  chp-host mesh add http://{ts_ip}:{port}")
    return 0


def _install_gateway_service(chp_dir: Path, yes: bool = False) -> None:
    from .service import install_service, _launchd_plist_path
    from .mesh import mesh_path

    mesh_file = mesh_path()
    if not mesh_file.exists():
        from .mesh import save_mesh, _empty_mesh
        save_mesh(_empty_mesh())
        print(f"  Created empty mesh manifest: {mesh_file}")

    # Write a gateway profile pointing at the mesh manifest
    gw_profile_path = chp_dir / "config" / "gateway.json"
    gw_profile_data = {
        "host_id": "chp-gateway-mesh",
        "bind": "0.0.0.0",
        "port": 8800,
        "store": str(chp_dir / "gateway-mesh.sqlite"),
        "secrets": ["CHP_MAC_KEY"],
        "adapters": [],
    }
    gw_profile_path.write_text(json.dumps(gw_profile_data, indent=2) + "\n")

    gw_unit = "chp-gateway-mesh"
    # Generate a custom plist that runs `chp-host gateway` (not `serve`)
    from .service import _launchd_plist_path, _build_launchd_plist, _python_exe
    import sys as _sys
    log_dir = chp_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    label = gw_unit.replace("-", ".")
    plist_content = _build_launchd_plist(
        label=label,
        python=_python_exe(),
        profile_path=str(mesh_file),
        host_id="chp-gateway-mesh",
        log_dir=str(log_dir),
        secrets=["CHP_MAC_KEY"],
    )
    # The default plist runs `serve --profile`; gateway needs `gateway --environment`.
    # Patch the plist to use gateway mode.
    plist_content = plist_content.replace(
        "<string>serve</string>\n    <string>--profile</string>",
        "<string>gateway</string>\n    <string>--environment</string>",
    ).replace(
        f"<string>{str(mesh_file)}</string>",
        "<string>mesh</string>",
    )
    plist_path = _launchd_plist_path(gw_unit, system=False)
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(plist_content)
    print(f"  Gateway plist: {plist_path}")

    r = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  Gateway service loaded: launchctl load {plist_path}")
    else:
        print(f"  WARNING: gateway launchctl load failed: {r.stderr.strip()}")
        print(f"  Run manually: launchctl load {plist_path}")


# ---------------------------------------------------------------------------
# chp-host mesh subcommands
# ---------------------------------------------------------------------------

def _cmd_mesh_invite(args: argparse.Namespace) -> int:
    from .mesh import load_mesh, next_peer_key_name, add_remote

    role = getattr(args, "role", "worker") or "worker"
    url = getattr(args, "url", None)

    data = load_mesh()
    key_name = next_peer_key_name(data)
    api_key = _secrets_mod.token_urlsafe(32)

    if sys.platform == "darwin":
        ok = _store_keychain(key_name, api_key)
        if ok:
            print(f"Stored {key_name!r} in Keychain (com.chp.secrets)")
        else:
            print(f"WARNING: Keychain store failed for {key_name!r}")
    else:
        print(f"Generated key for {key_name!r} — store it securely:")

    if url:
        add_remote(url, api_key_env=key_name, role=role)
        print(f"Added {url!r} to mesh as {role!r} using {key_name!r}")

    port = 8803
    print(f"\n✓ Invite generated ({key_name}).")
    print(f"\n  On the WORKER machine, run:")
    print(f"    chp-host secrets set CHP_HOST_API_KEY")
    print(f"    (enter: {api_key})")
    print(f"\n  Then start the worker:")
    print(f"    chp-host init --role {role} --yes")
    if not url:
        print(f"\n  When the worker is running, register it here:")
        print(f"    chp-host mesh add http://<worker-ip>:{port} --role {role}")
        print(f"    (key {key_name!r} is already stored)")
    print(f"\n  KEY VALUE (keep secure): {api_key}")
    return 0


def _cmd_mesh_add(args: argparse.Namespace) -> int:
    from .mesh import load_mesh, next_peer_key_name, add_remote

    url = args.url.rstrip("/")
    role = getattr(args, "role", "worker") or "worker"
    key_name = getattr(args, "key_name", None)

    # Probe health
    try:
        resp = urllib.request.urlopen(f"{url}/health", timeout=5)
        health = json.loads(resp.read().decode())
        cap_count = health.get("capability_count", "?")
        print(f"  ✓ {url}/health → {cap_count} capabilities")
    except Exception as exc:
        print(f"ERROR: cannot reach {url}/health: {exc}", file=sys.stderr)
        return 1

    # Determine key env name
    if not key_name:
        data = load_mesh()
        key_name = next_peer_key_name(data)

    try:
        add_remote(url, api_key_env=key_name, role=role)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"  Added {url!r} to mesh as {role!r} (api_key_env: {key_name!r})")
    print(f"  Restart the gateway to pick up the new node:")
    print(f"    launchctl unload ~/Library/LaunchAgents/com.chp.chp-gateway-mesh.plist")
    print(f"    launchctl load   ~/Library/LaunchAgents/com.chp.chp-gateway-mesh.plist")
    return 0


def _cmd_mesh_list(args: argparse.Namespace) -> int:
    from .mesh import load_mesh, mesh_path, mark_verified

    data = load_mesh()
    remotes = data.get("agent_remotes") or []
    if not remotes:
        print(f"No remotes in {mesh_path()}. Use 'chp-host mesh add <url>' to join nodes.")
        return 0

    print(f"{'URL':<36} {'Role':<10} {'Status':<8} {'Caps':<6} {'Verified'}")
    print("-" * 80)
    for r in remotes:
        url = r.get("url", "")
        role = r.get("role", "?")
        status = "?"
        caps = "-"
        try:
            resp = urllib.request.urlopen(f"{url}/health", timeout=3)
            h = json.loads(resp.read().decode())
            caps = str(h.get("capability_count", "?"))
            status = "✓ OK"
            mark_verified(url)  # stamp last_verified so stale peers are visible
            verified = "just now"
        except Exception:
            status = "✗ FAIL"
            verified = (r.get("last_verified") or "never")[:10]
        print(f"{url:<36} {role:<10} {status:<8} {caps:<6} {verified}")
    return 0


def _cmd_mesh_remove(args: argparse.Namespace) -> int:
    from .mesh import remove_remote, mesh_path

    url = args.url.rstrip("/")
    try:
        freed_key = remove_remote(url)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Removed {url!r} from {mesh_path()}")
    if freed_key:
        print(f"Freed api_key_env: {freed_key!r}")
    return 0


def _cmd_mesh_revoke(args: argparse.Namespace) -> int:
    """Remove a remote AND delete its pre-shared key from the keychain.

    Use when a node is lost or decommissioned — `remove` only forgets the
    manifest entry; `revoke` also destroys the key so it can never re-auth.
    """
    from .mesh import remove_remote, mesh_path

    url = args.url.rstrip("/")
    try:
        key_env = remove_remote(url)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Revoked {url!r} from {mesh_path()}")
    if key_env:
        if sys.platform == "darwin" and _delete_keychain(key_env):
            print(f"  Deleted key {key_env!r} from Keychain")
        else:
            print(f"  Remove the key manually: chp-host secrets delete {key_env}")
    print("  Restart the gateway to drop the revoked node.")
    return 0


def _cmd_mesh_rotate(args: argparse.Namespace) -> int:
    """Generate a fresh pre-shared key for a remote and store it locally.

    Prints the new key once so the operator can set it on the peer
    (`chp-host secrets set CHP_HOST_API_KEY` there, then restart it). The
    manifest's api_key_env is unchanged — only the secret value rotates.
    """
    from .mesh import find_remote

    url = args.url.rstrip("/")
    remote = find_remote(url)
    if remote is None:
        print(f"ERROR: Remote {url!r} not found in mesh manifest.", file=sys.stderr)
        return 1

    key_env = remote.get("api_key_env")
    if not key_env:
        print(f"ERROR: Remote {url!r} has no api_key_env to rotate.", file=sys.stderr)
        return 1

    if sys.platform != "darwin":
        print("ERROR: key rotation uses the macOS Keychain backend.", file=sys.stderr)
        return 1

    new_key = _secrets_mod.token_urlsafe(32)
    if not _store_keychain(key_env, new_key):
        print(f"ERROR: could not store rotated key {key_env!r} in Keychain.", file=sys.stderr)
        return 1

    print(f"Rotated {key_env!r} for {url!r}.")
    print(f"\n  NEW KEY (set on the peer, then restart it):\n    {new_key}")
    print("\n  On the peer:")
    print("    chp-host secrets set CHP_HOST_API_KEY   # paste the key above")
    print("    launchctl unload ~/Library/LaunchAgents/com.chp.chp.host.*.plist && \\")
    print("    launchctl load   ~/Library/LaunchAgents/com.chp.chp.host.*.plist")
    print("\n  Then restart the local gateway to reconnect.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chp-host", description="CHP multi-host tooling.")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Serve a real host from named adapters over HTTP.")
    serve.add_argument("--adapters", help="Comma-separated adapter names (e.g. aws,azure,gcp).")
    serve.add_argument("--profile", help="Path to a host profile JSON file.")
    serve.add_argument("--environment", help="Environment name (loads environments/{name}.json).")
    serve.add_argument("--env-dir", help="Base directory for environments/ lookup (default: cwd).")
    serve.add_argument("--host-id", default="chp-host", help="Host id (default: chp-host).")
    serve.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    serve.add_argument("--port", type=int, default=8765, help="Port (default: 8765).")
    serve.add_argument("--store", default=".chp/host.sqlite", help="Evidence store path.")
    serve.add_argument(
        "--secrets-from-keychain",
        nargs="+",
        metavar="KEY",
        help="Inject these key names from macOS Keychain (com.chp.secrets) into env before starting.",
    )
    serve.set_defaults(func=_cmd_serve)

    mcp_cmd = sub.add_parser("mcp", help="Serve adapters as MCP tools over stdio (for Claude Code).")
    mcp_cmd.add_argument("--adapters", help="Comma-separated adapter names (e.g. git,github,planning).")
    mcp_cmd.add_argument("--profile", help="Path to a host profile JSON file.")
    mcp_cmd.add_argument(
        "--environment",
        help="Environment name — routes through a MultiHostRouter across all hosts in the manifest.",
    )
    mcp_cmd.add_argument("--env-dir", help="Base directory for environments/ lookup (default: cwd).")
    mcp_cmd.add_argument("--host-id", default="chp", help="MCP server name (default: chp).")
    mcp_cmd.add_argument("--store", default=":memory:", help="Evidence store path (default: :memory:).")
    mcp_cmd.add_argument(
        "--min-status",
        choices=["draft", "experimental", "certified"],
        default="draft",
        help="Minimum capability status to expose (default: draft). Use 'experimental' or 'certified' in production.",
    )
    mcp_cmd.add_argument(
        "--secrets-from-keychain",
        nargs="+",
        metavar="KEY",
        help="Inject these key names from macOS Keychain (com.chp.secrets) into env before starting.",
    )
    mcp_cmd.set_defaults(func=_cmd_mcp)

    init_cmd = sub.add_parser(
        "init",
        help="First-run guided setup — generate key, write profile, install + load service.",
    )
    init_cmd.add_argument(
        "--role",
        choices=list(_ROLE_PROFILES),
        help="Node role (auto-detected from platform if omitted).",
    )
    init_cmd.add_argument("--port", type=int, default=None, help="Override the default port for this role.")
    init_cmd.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts.")
    init_cmd.set_defaults(func=_cmd_init)

    mesh_cmd = sub.add_parser("mesh", help="Manage the mesh manifest (~/.chp/mesh.json).")
    mesh_sub = mesh_cmd.add_subparsers(dest="mesh_action", required=True)

    mesh_invite = mesh_sub.add_parser("invite", help="Generate a pre-shared key and print the worker join command.")
    mesh_invite.add_argument("--role", default="worker", choices=list(_ROLE_PROFILES), help="Role for the invited node.")
    mesh_invite.add_argument("--url", help="If known, add the remote URL to mesh.json immediately.")
    mesh_invite.set_defaults(func=_cmd_mesh_invite)

    mesh_add = mesh_sub.add_parser("add", help="Add a running CHP host to the mesh.")
    mesh_add.add_argument("url", help="Base URL of the CHP host (e.g. http://100.1.2.3:8803).")
    mesh_add.add_argument("--role", default="worker", choices=list(_ROLE_PROFILES), help="Role label.")
    mesh_add.add_argument("--key-name", dest="key_name", help="api_key_env name to use (default: CHP_PEER_n_KEY).")
    mesh_add.set_defaults(func=_cmd_mesh_add)

    mesh_list = mesh_sub.add_parser("list", help="List mesh remotes and probe their health.")
    mesh_list.set_defaults(func=_cmd_mesh_list)

    mesh_remove = mesh_sub.add_parser("remove", help="Remove a remote from the mesh manifest.")
    mesh_remove.add_argument("url", help="URL to remove.")
    mesh_remove.set_defaults(func=_cmd_mesh_remove)

    mesh_revoke = mesh_sub.add_parser(
        "revoke", help="Remove a remote and delete its pre-shared key from the keychain.")
    mesh_revoke.add_argument("url", help="URL to revoke.")
    mesh_revoke.set_defaults(func=_cmd_mesh_revoke)

    mesh_rotate = mesh_sub.add_parser(
        "rotate", help="Generate a fresh pre-shared key for a remote (set it on the peer).")
    mesh_rotate.add_argument("url", help="URL whose key to rotate.")
    mesh_rotate.set_defaults(func=_cmd_mesh_rotate)

    gw_cmd = sub.add_parser(
        "gateway",
        help="Serve a CHP HTTP gateway routing across all agent_remotes in an environment.",
    )
    gw_cmd.add_argument(
        "--environment",
        required=False,
        default=None,
        help="Environment name (loads environments/{name}.json). Defaults to ~/.chp/mesh.json.",
    )
    gw_cmd.add_argument("--env-dir", help="Base directory for environments/ lookup (default: cwd).")
    gw_cmd.add_argument("--host-id", default=None, help="Gateway host-id (default: from manifest or 'chp-gateway').")
    gw_cmd.add_argument("--bind", default=None, help="Bind address override (default: from manifest or 0.0.0.0).")
    gw_cmd.add_argument("--port", type=int, default=None, help="Port override (default: from manifest or 8800).")
    gw_cmd.add_argument(
        "--secrets-from-keychain",
        dest="secrets_from_keychain",
        nargs="+",
        metavar="KEY",
        default=[],
        help="Inject KEY=value from macOS Keychain into environment before starting.",
    )
    gw_cmd.set_defaults(func=_cmd_gateway)

    secrets_cmd = sub.add_parser("secrets", help="Manage CHP secrets in macOS Keychain (com.chp.secrets).")
    secrets_sub = secrets_cmd.add_subparsers(dest="secrets_action", required=True)
    s_set = secrets_sub.add_parser("set", help="Store a secret (prompted securely).")
    s_set.add_argument("key", help="Secret key name, e.g. GITHUB_TOKEN.")
    s_set.add_argument("--stdin", action="store_true", help="Read value from stdin instead of prompt.")
    s_get = secrets_sub.add_parser("get", help="Print a secret value.")
    s_get.add_argument("key")
    s_del = secrets_sub.add_parser("delete", help="Remove a secret from the Keychain.")
    s_del.add_argument("key")
    secrets_sub.add_parser("list", help="List stored secret key names.")
    secrets_cmd.set_defaults(func=_cmd_secrets)

    adapters_cmd = sub.add_parser("adapters", help="List installed chp.adapters entry points.")
    adapters_cmd.add_argument(
        "--registry",
        action="store_true",
        help="Compare installed adapters against the public registry.",
    )
    adapters_cmd.set_defaults(func=_cmd_adapters)

    envs_cmd = sub.add_parser("environments", help="List available environment manifests.")
    envs_cmd.add_argument("--env-dir", help="Directory to scan for environment JSON files.")
    envs_cmd.set_defaults(func=_cmd_environments)

    status_cmd = sub.add_parser("status", help="Show status of running CHP hosts.")
    status_cmd.add_argument("--environment", help="Environment name to check host status for.")
    status_cmd.add_argument("--env-dir", help="Base directory for environments/ and .chp/ lookup.")
    status_cmd.add_argument("--mesh", action="store_true", help="Also show mesh remotes from ~/.chp/mesh.json.")
    status_cmd.set_defaults(func=_cmd_status)

    svc_install = sub.add_parser(
        "install-service",
        help="Generate a systemd unit (Linux) or launchd plist (macOS) for a host profile.",
    )
    svc_install.add_argument("--profile", required=True, help="Path to a host profile JSON file.")
    svc_install.add_argument("--unit-name", help="Service unit name (default: chp-host-<host_id>).")
    svc_install.add_argument("--user", help="Run-as user for systemd unit (default: current user).")
    svc_install.add_argument(
        "--system",
        action="store_true",
        default=False,
        help="Install as a system-wide service (requires root). Default: user-level service.",
    )
    svc_install.add_argument(
        "--secrets",
        nargs="+",
        metavar="KEY",
        help=(
            "Secret key names to inject from macOS Keychain at service startup "
            "(launchd: via --secrets-from-keychain; systemd: env stub). "
            "Defaults to the 'secrets' list in the profile."
        ),
    )
    svc_install.set_defaults(func=_cmd_install_service)

    svc_uninstall = sub.add_parser(
        "uninstall-service",
        help="Remove a generated systemd unit or launchd plist.",
    )
    svc_uninstall.add_argument("--unit-name", required=True, help="Service unit name to remove.")
    svc_uninstall.add_argument(
        "--system",
        action="store_true",
        default=False,
        help="Remove from system-level location (default: user-level).",
    )
    svc_uninstall.set_defaults(func=_cmd_uninstall_service)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
