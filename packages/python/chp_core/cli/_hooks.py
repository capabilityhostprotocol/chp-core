"""CHP CLI hook processing and Claude Code hooks management commands."""

from __future__ import annotations

import argparse
import json


def _settings_path(global_scope: bool, project: bool) -> str:
    from pathlib import Path
    if project:
        return str(Path(".claude") / "settings.json")
    return str(Path.home() / ".claude" / "settings.json")


def _install_hooks(settings_path: str, with_governance: bool = False) -> None:
    """Add CHP hooks to a Claude Code settings.json file (idempotent)."""
    from pathlib import Path

    path = Path(settings_path)
    settings: dict = {}
    if path.exists():
        with path.open() as f:
            settings = json.load(f)

    hooks = settings.setdefault("hooks", {})

    def _existing_commands(event: str) -> list[str]:
        return [
            h["command"]
            for entry in hooks.get(event, [])
            for h in entry.get("hooks", [])
            if h.get("type") == "command"
        ]

    if with_governance and "chp hook pre-tool" not in _existing_commands("PreToolUse"):
        hooks.setdefault("PreToolUse", []).append({
            "matcher": "",
            "hooks": [{"type": "command", "command": "chp hook pre-tool", "timeout": 5}],
        })

    if "chp hook post-tool" not in _existing_commands("PostToolUse"):
        hooks.setdefault("PostToolUse", []).append({
            "matcher": "",
            "hooks": [{"type": "command", "command": "chp hook post-tool", "timeout": 5}],
        })

    if "chp hook stop" not in _existing_commands("Stop"):
        hooks.setdefault("Stop", []).append({
            "hooks": [{"type": "command", "command": "chp hook stop", "timeout": 5}],
        })

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(settings, f, indent=2)


def _uninstall_hooks(settings_path: str) -> None:
    """Remove CHP hooks from a Claude Code settings.json file."""
    from pathlib import Path

    path = Path(settings_path)
    if not path.exists():
        return

    with path.open() as f:
        settings = json.load(f)

    hooks = settings.get("hooks", {})
    chp_commands = {"chp hook pre-tool", "chp hook post-tool", "chp hook stop"}

    for event in ("PreToolUse", "PostToolUse", "Stop"):
        entries = hooks.get(event, [])
        cleaned = []
        for entry in entries:
            remaining = [h for h in entry.get("hooks", []) if h.get("command") not in chp_commands]
            if remaining:
                cleaned.append({**entry, "hooks": remaining})
        if cleaned:
            hooks[event] = cleaned
        elif event in hooks:
            del hooks[event]

    with path.open("w") as f:
        json.dump(settings, f, indent=2)


def cmd_hook_pre_tool(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import default_store_path, process_pre_tool_use
    from ..policy import load_policy

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        policy = load_policy(getattr(args, "policy", None))
        result = process_pre_tool_use(payload, store_path, policy=policy)
        if result.should_block:
            print(f"CHP: blocked — {result.reason}", file=sys.stderr)
            return 2
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_post_tool(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import default_store_path, process_post_tool_use

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_post_tool_use(payload, store_path)
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_stop(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import default_store_path, process_stop

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_stop(payload, store_path)
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_codex_post_tool(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import CODEX_TOOL_CAPABILITY_MAP, default_store_path, process_post_tool_use

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_post_tool_use(payload, store_path, tool_map=CODEX_TOOL_CAPABILITY_MAP, agent_prefix="codex")
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_codex_stop(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import default_store_path, process_stop

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_stop(payload, store_path, agent_prefix="codex")
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_gemini_post_tool(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import GEMINI_TOOL_CAPABILITY_MAP, default_store_path, process_post_tool_use

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_post_tool_use(payload, store_path, tool_map=GEMINI_TOOL_CAPABILITY_MAP, agent_prefix="gemini")
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_gemini_stop(args: argparse.Namespace) -> int:
    import sys
    from ..hooks import default_store_path, process_stop

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        process_stop(payload, store_path, agent_prefix="gemini")
    except Exception:  # noqa: BLE001
        pass
    return 0


_PRECOMMIT_HOOK = """\
#!/bin/sh
cd "$(git rev-parse --show-toplevel)"
PYTHONPATH=packages/python python -m chp_core.cli work vc precommit \\
  --check tests \\
  --check alignment \\
  --check conformance \\
  --check schemas \\
  --repo-root . 2>&1
"""

# Pre-push hook: blocks bare version tags (v1.2.3) that lack a matching RC tag
# (v1.2.3-rc.*), mirroring the verify-staged guard in release.yml. Also runs
# conformance + schema validation before any push to the tracked remote.
_PRE_PUSH_HOOK = """\
#!/bin/sh
# CHP pre-push: enforce RC-before-production-tag rule and run fast CI checks.
#
# production tag push (v1.2.3)  →  requires v1.2.3-rc.* to exist locally
# RC tag push (v1.2.3-rc.1)     →  allowed freely
# branch push                   →  allowed freely (CI covers it)

REMOTE="$1"
FAIL=0

while read local_ref local_sha remote_ref remote_sha; do
    case "$remote_ref" in refs/tags/v*) ;; *) continue ;; esac

    TAG="${remote_ref#refs/tags/}"

    # RC tags are fine
    case "$TAG" in *-rc.*) continue ;; esac

    # Bare version tag — require a matching RC tag locally
    VERSION="${TAG#v}"
    RC_PATTERN="v${VERSION}-rc.*"
    MATCHES=$(git tag --list "$RC_PATTERN")

    if [ -z "$MATCHES" ]; then
        printf '\\n'
        printf 'ERROR: Blocked push of production tag %s to %s\\n' "$TAG" "$REMOTE"
        printf '\\n'
        printf '  No RC tag found matching: %s\\n' "$RC_PATTERN"
        printf '\\n'
        printf '  Run the staging flow first:\\n'
        printf '    git tag %s-rc.1 && git push github %s-rc.1\\n' "$TAG" "$TAG"
        printf '  Wait for staging.yml to pass, then re-push the production tag.\\n'
        printf '\\n'
        FAIL=1
    fi
done

[ "$FAIL" -ne 0 ] && exit 1

# Fast checks that mirror CI — conformance, schema validation, and a
# collect-only dry run inside a clean venv (catches missing-dep import errors
# before they reach GitHub Actions).
cd "$(git rev-parse --show-toplevel)"
PYTHONPATH=packages/python python -m chp_core.cli work vc precommit \\
    --check conformance \\
    --check schemas \\
    --check collect-check \\
    --repo-root . 2>&1
"""


def _install_precommit_hook() -> str:
    from pathlib import Path
    import stat

    git_hooks = Path(".git") / "hooks"
    if not git_hooks.is_dir():
        raise FileNotFoundError(".git/hooks not found — run from the repo root")
    hook_path = git_hooks / "pre-commit"
    hook_path.write_text(_PRECOMMIT_HOOK)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(hook_path)


def _install_prepush_hook() -> str:
    from pathlib import Path
    import stat

    git_hooks = Path(".git") / "hooks"
    if not git_hooks.is_dir():
        raise FileNotFoundError(".git/hooks not found — run from the repo root")
    hook_path = git_hooks / "pre-push"
    hook_path.write_text(_PRE_PUSH_HOOK)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(hook_path)


def cmd_hooks_install(args: argparse.Namespace) -> int:
    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    _install_hooks(path, with_governance=getattr(args, "with_governance", False))
    print(f"CHP hooks installed in {path}")
    if getattr(args, "with_precommit", False):
        hook_path = _install_precommit_hook()
        print(f"Pre-commit hook installed in {hook_path}")
    if getattr(args, "with_prepush", False):
        hook_path = _install_prepush_hook()
        print(f"Pre-push hook installed in {hook_path}")
    return 0


def cmd_hooks_uninstall(args: argparse.Namespace) -> int:
    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    _uninstall_hooks(path)
    print(f"CHP hooks removed from {path}")
    return 0


def cmd_hooks_status(args: argparse.Namespace) -> int:
    from pathlib import Path

    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    p = Path(path)
    if not p.exists():
        print(f"Settings not found: {path}")
        return 0

    with p.open() as f:
        settings = json.load(f)

    hooks = settings.get("hooks", {})

    def _has_command(event: str, cmd: str) -> bool:
        return cmd in [
            h["command"]
            for entry in hooks.get(event, [])
            for h in entry.get("hooks", [])
            if h.get("type") == "command"
        ]

    print(f"Settings: {path}")
    print(f"  PreToolUse hook:  {'installed' if _has_command('PreToolUse', 'chp hook pre-tool') else 'not installed'}")
    print(f"  PostToolUse hook: {'installed' if _has_command('PostToolUse', 'chp hook post-tool') else 'not installed'}")
    print(f"  Stop hook:        {'installed' if _has_command('Stop', 'chp hook stop') else 'not installed'}")
    return 0
