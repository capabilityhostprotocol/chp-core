"""Service file generation for chp-host — systemd (Linux) and launchd (macOS).

Generates a unit file / plist that starts ``chp-host serve --profile <path>``
as a system service. The caller is expected to copy/load the file using the
printed instructions; this module only writes the file itself.

Usage::

    from chp_host.service import install_service, uninstall_service
    install_service(profile_path, unit_name="chp-host-raspi", system=False,
                    secrets=["CHP_HOST_API_KEY"])
    uninstall_service(unit_name="chp-host-raspi")
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _python_exe() -> str:
    return sys.executable


def _detect_format() -> str:
    if sys.platform == "linux":
        return "systemd"
    if sys.platform == "darwin":
        return "launchd"
    raise RuntimeError(
        f"Service installation is not supported on {sys.platform}. "
        "Supported platforms: linux (systemd), darwin (launchd)."
    )


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

_SYSTEMD_UNIT = """\
[Unit]
Description=CHP Host: {host_id}
After=network.target

[Service]
Type=simple
User={user}
ExecStart={python} -m chp_host.cli serve --profile {profile_path}{secrets_args}
Restart=on-failure
RestartSec=5
EnvironmentFile=-%h/.chp/{host_id}.env

[Install]
WantedBy=multi-user.target
"""


def _systemd_unit_path(unit_name: str, system: bool) -> Path:
    if system:
        return Path(f"/etc/systemd/system/{unit_name}.service")
    return Path.home() / ".config" / "systemd" / "user" / f"{unit_name}.service"


def _install_systemd(
    profile_path: str,
    host_id: str,
    unit_name: str,
    user: str,
    system: bool,
    secrets: list[str],
) -> None:
    secrets_args = ""
    if secrets:
        key_list = " ".join(secrets)
        secrets_args = f" --secrets-from-keychain {key_list}"

    content = _SYSTEMD_UNIT.format(
        host_id=host_id,
        user=user,
        python=_python_exe(),
        profile_path=Path(profile_path).resolve(),
        secrets_args=secrets_args,
    )
    dest = _systemd_unit_path(unit_name, system)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)

    env_stub = Path.home() / ".chp" / f"{host_id}.env"
    if not env_stub.exists():
        env_stub.parent.mkdir(parents=True, exist_ok=True)
        env_stub.write_text("# CHP host environment overrides\n# Add KEY=VALUE pairs here.\n")

    scope = "--system" if system else "--user"
    print(f"Wrote: {dest}")
    if not secrets:
        print(f"\nSet secrets in {env_stub}:")
        print(f"  CHP_HOST_API_KEY=<your-key>")
    print(f"\nTo enable and start:")
    print(f"  systemctl {scope} daemon-reload")
    print(f"  systemctl {scope} enable {unit_name}")
    print(f"  systemctl {scope} start {unit_name}")


def _uninstall_systemd(unit_name: str, system: bool) -> None:
    dest = _systemd_unit_path(unit_name, system)
    scope = "--system" if system else "--user"
    if not dest.exists():
        print(f"Service file not found: {dest}")
        return
    dest.unlink()
    print(f"Removed: {dest}")
    print(f"\nTo stop and disable:")
    print(f"  systemctl {scope} stop {unit_name}")
    print(f"  systemctl {scope} disable {unit_name}")
    print(f"  systemctl {scope} daemon-reload")


# ---------------------------------------------------------------------------
# launchd
# ---------------------------------------------------------------------------

_LAUNCHD_PLIST_HEAD = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.chp.{label}</string>

  <key>ProgramArguments</key>
  <array>
    <string>{python}</string>
    <string>-m</string>
    <string>chp_host.cli</string>
    <string>serve</string>
    <string>--profile</string>
    <string>{profile_path}</string>
"""

_LAUNCHD_PLIST_SECRETS_ENTRY = """\
    <string>--secrets-from-keychain</string>
"""

_LAUNCHD_PLIST_TAIL = """\
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>{log_dir}/{host_id}.log</string>

  <key>StandardErrorPath</key>
  <string>{log_dir}/{host_id}.err</string>
</dict>
</plist>
"""


def _build_launchd_plist(
    label: str,
    python: str,
    profile_path: str,
    host_id: str,
    log_dir: str,
    secrets: list[str],
) -> str:
    parts = [_LAUNCHD_PLIST_HEAD.format(
        label=label,
        python=python,
        profile_path=profile_path,
    )]
    if secrets:
        parts.append(_LAUNCHD_PLIST_SECRETS_ENTRY)
        for key in secrets:
            parts.append(f"    <string>{key}</string>\n")
    parts.append(_LAUNCHD_PLIST_TAIL.format(
        host_id=host_id,
        log_dir=log_dir,
    ))
    return "".join(parts)


def _launchd_plist_path(unit_name: str, system: bool) -> Path:
    label = unit_name.replace("-", ".")
    if system:
        return Path(f"/Library/LaunchDaemons/com.chp.{label}.plist")
    return Path.home() / "Library" / "LaunchAgents" / f"com.chp.{label}.plist"


def _install_launchd(
    profile_path: str,
    host_id: str,
    unit_name: str,
    system: bool,
    secrets: list[str],
) -> None:
    log_dir = Path.home() / ".chp" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    label = unit_name.replace("-", ".")
    content = _build_launchd_plist(
        label=label,
        python=_python_exe(),
        profile_path=str(Path(profile_path).resolve()),
        host_id=host_id,
        log_dir=str(log_dir),
        secrets=secrets,
    )
    dest = _launchd_plist_path(unit_name, system)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    print(f"Wrote: {dest}")
    if not secrets:
        print(f"\nIMPORTANT: The service has no secrets configured.")
        print(f"Pass --secrets KEY1 KEY2 to inject keys from macOS Keychain at launch.")
    print(f"\nTo load and start:")
    print(f"  launchctl load {dest}")
    print(f"\nTo check status:")
    print(f"  launchctl list com.chp.{label}")
    print(f"\nLogs: {log_dir}/{host_id}.log")


def _uninstall_launchd(unit_name: str, system: bool) -> None:
    dest = _launchd_plist_path(unit_name, system)
    label = unit_name.replace("-", ".")
    if dest.exists():
        print(f"To unload first:")
        print(f"  launchctl unload {dest}")
        dest.unlink()
        print(f"Removed: {dest}")
    else:
        print(f"Service file not found: {dest}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install_service(
    profile_path: str,
    host_id: str,
    unit_name: str,
    system: bool = False,
    user: str | None = None,
    secrets: list[str] | None = None,
) -> None:
    """Generate and write a systemd unit or launchd plist for a chp-host profile.

    secrets — key names to read from macOS Keychain (launchd) or write to
              ~/.chp/{host_id}.env stub (systemd) at service startup.
    """
    resolved_secrets: list[str] = secrets or []
    fmt = _detect_format()
    if fmt == "systemd":
        _install_systemd(
            profile_path=profile_path,
            host_id=host_id,
            unit_name=unit_name,
            user=user or os.environ.get("USER", "root"),
            system=system,
            secrets=resolved_secrets,
        )
    else:
        _install_launchd(
            profile_path=profile_path,
            host_id=host_id,
            unit_name=unit_name,
            system=system,
            secrets=resolved_secrets,
        )


def uninstall_service(unit_name: str, system: bool = False) -> None:
    """Remove the generated service file."""
    fmt = _detect_format()
    if fmt == "systemd":
        _uninstall_systemd(unit_name=unit_name, system=system)
    else:
        _uninstall_launchd(unit_name=unit_name, system=system)
