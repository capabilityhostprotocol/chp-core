"""CHP CLI hook processing and Claude Code hooks management commands."""

from __future__ import annotations

import argparse
import json


def _settings_path(global_scope: bool, project: bool) -> str:
    from pathlib import Path
    if project:
        return str(Path(".claude") / "settings.json")
    return str(Path.home() / ".claude" / "settings.json")


def _install_hooks(settings_path: str, with_governance: bool = False,
                   store: str | None = None) -> None:
    """Add CHP hooks to a Claude Code settings.json file (idempotent). ``store`` routes the pre-tool
    gate's evidence (incl. denials) to a shared store so every harness feeds one evidence plane."""
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

    pre_cmd = "chp hook pre-tool" + (f" --store {store}" if store else "")
    if with_governance and not any("chp hook pre-tool" in c for c in _existing_commands("PreToolUse")):
        hooks.setdefault("PreToolUse", []).append({
            "matcher": "",
            "hooks": [{"type": "command", "command": pre_cmd, "timeout": 5}],
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


def _default_hook_store() -> str:
    from pathlib import Path
    return str(Path.home() / ".chp" / "hook-evidence.sqlite")


def _default_policy() -> dict:
    """The shipped standard: catastrophic absolutes, quote-masked, wildcard across every harness.
    Mirrors the built-in floor (belt-and-suspenders) + adds the tunable power/reboot rule."""
    def rule(pattern: str, reason: str) -> dict:
        return {"capability_id": "*", "field": "command", "unquoted": True,
                "pattern": pattern, "reason": reason, "decision": "deny"}
    return {"version": "chp-standards-2", "block_patterns": [
        rule("--no-verify", "CHP standard: never bypass verification hooks (--no-verify)"),
        rule(r"rm\s+-[rfRF]*r[rfRF]*\s+(/|~|\$HOME)(\s|/|\*|$)",
             "CHP standard: refused catastrophic recursive delete of a root/home target"),
        rule(r"\bmkfs", "CHP standard: refused filesystem format"),
        rule(r"\bdd\s+if=.*of=/dev/", "CHP standard: refused dd write to a raw device"),
        rule(r":\(\)\s*\{\s*:\s*\|", "CHP standard: refused fork bomb"),
        rule(r">\s*/dev/(sd|disk|nvme|hd)", "CHP standard: refused overwrite of a raw disk device"),
        rule(r"\b(shutdown|reboot|halt)\b", "CHP standard: refused power/reboot command"),
    ]}


def _write_default_policy() -> str | None:
    """Write the default policy only if none exists — never clobber a tuned one."""
    from pathlib import Path
    path = Path.home() / ".chp" / "policy.json"
    if path.exists():
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(_default_policy(), f, indent=2)
    return str(path)


def _install_gemini_hooks(store: str, chp_bin: str) -> str:
    """Wire the pre-tool gate into Gemini CLI settings.json (idempotent). Gemini's shell tool is
    ``run_shell_command`` — matched by ``.*shell.*``."""
    from pathlib import Path
    path = Path.home() / ".gemini" / "settings.json"
    settings: dict = {}
    if path.exists():
        with path.open() as f:
            settings = json.load(f)
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    cmds = [h.get("command", "") for e in pre for h in e.get("hooks", [])]
    if not any("gemini-pre-tool" in c for c in cmds):
        pre.append({"matcher": ".*shell.*", "hooks": [
            {"type": "command", "command": f"{chp_bin} hook gemini-pre-tool --store {store}",
             "timeout": 10}]})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(settings, f, indent=2)
    return str(path)


def _install_codex_hooks(store: str, chp_bin: str) -> str:
    """Wire the pre-tool gate into Codex CLI config.toml (idempotent). Codex PreToolUse fires for the
    Bash tool only; needs ``[features] hooks = true``. Text-level edit — TOML allows one [features]
    table, so we insert into it rather than append a duplicate."""
    import re as _re
    from pathlib import Path
    path = Path.home() / ".codex" / "config.toml"
    text = path.read_text() if path.exists() else ""
    if "codex-pre-tool" in text:
        return str(path)  # already wired
    if _re.search(r"(?m)^\s*hooks\s*=\s*true", text) is None:
        if _re.search(r"(?m)^\[features\]\s*$", text):
            text = _re.sub(r"(?m)^\[features\]\s*$", "[features]\nhooks = true", text, count=1)
        else:
            text = text.rstrip() + "\n\n[features]\nhooks = true\n"
    block = (
        "\n# CHP governance: block consequential shell commands via the shared policy gate.\n"
        '[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n\n'
        "[[hooks.PreToolUse.hooks]]\n"
        'type = "command"\n'
        f"command = '{chp_bin} hook codex-pre-tool --store {store}'\n"
        "timeout = 10\n"
    )
    text = text.rstrip() + "\n" + block
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return str(path)


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


def _run_pre_tool(args: argparse.Namespace, tool_map: dict[str, str] | None = None,
                  agent_prefix: str = "claude_code") -> int:
    """Shared PreToolUse enforcement for every harness. All three (Claude Code, Codex, Gemini) send
    Claude-shaped events (``tool_name`` + ``tool_input``) and block on exit 2, so the same policy
    engine governs each — ``tool_map``/``agent_prefix`` only steer capability-id derivation so evidence
    is attributed to the right harness."""
    import sys
    from ..hooks import default_store_path, process_pre_tool_use
    from ..policy import load_policy

    store_path = args.store if args.store else default_store_path()
    try:
        payload = json.loads(sys.stdin.read())
        policy = load_policy(getattr(args, "policy", None))
        result = process_pre_tool_use(payload, store_path, policy=policy,
                                      tool_map=tool_map, agent_prefix=agent_prefix)
        if result.should_block:
            print(f"CHP: blocked — {result.reason}", file=sys.stderr)
            return 2
    except Exception:  # noqa: BLE001
        pass
    return 0


def cmd_hook_pre_tool(args: argparse.Namespace) -> int:
    return _run_pre_tool(args)


_SELFTEST_MUST_BLOCK = [
    "git commit --no-verify -m x",
    "rm -rf /",
    "rm -rf ~/",
    "sudo mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
]
_SELFTEST_MUST_PASS = [
    "git status",
    "rm -rf ./build",
    "npm run build",
    'git commit -m "note about --no-verify in the changelog"',  # a mention, not the real flag
]


def cmd_hook_selftest(args: argparse.Namespace) -> int:
    """Assert the gate blocks the known-bad set and passes the known-good set, using the SAME floor +
    policy the hooks do — so a policy regression (a broken regex, a missing ``unquoted``) fails LOUDLY
    here instead of silently fail-open at runtime. Exit 0 = all pass; 1 = at least one mismatch."""
    import sys
    from ..policy import evaluate_policy, floor_violation, load_policy

    policy = load_policy(getattr(args, "policy", None))

    def would_block(cmd: str) -> bool:
        # mirrors process_pre_tool_use: fail-closed floor first, then the wildcard policy
        if floor_violation(cmd):
            return True
        if policy is None:
            return False
        return evaluate_policy("selftest.shell", {"command": cmd}, policy).should_block

    print(f"CHP hook selftest — policy: {getattr(args, 'policy', None) or '(auto-located)'}"
          f"{' [NONE — floor only]' if policy is None else ''}")
    failures = 0
    for cmd in _SELFTEST_MUST_BLOCK:
        ok = would_block(cmd)
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] blocks  {cmd}")
    for cmd in _SELFTEST_MUST_PASS:
        ok = not would_block(cmd)
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] allows  {cmd}")
    total = len(_SELFTEST_MUST_BLOCK) + len(_SELFTEST_MUST_PASS)
    print(f"{total - failures}/{total} checks passed")
    if failures:
        print(f"CHP: selftest FAILED — {failures} check(s); the gate is NOT enforcing the standard",
              file=sys.stderr)
        return 1
    return 0


def cmd_hook_codex_pre_tool(args: argparse.Namespace) -> int:
    from ..hooks import CODEX_TOOL_CAPABILITY_MAP
    return _run_pre_tool(args, tool_map=CODEX_TOOL_CAPABILITY_MAP, agent_prefix="codex")


def cmd_hook_gemini_pre_tool(args: argparse.Namespace) -> int:
    from ..hooks import GEMINI_TOOL_CAPABILITY_MAP
    return _run_pre_tool(args, tool_map=GEMINI_TOOL_CAPABILITY_MAP, agent_prefix="gemini")


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
  --check mypy \\
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
    --check mypy \\
    --check collect-check \\
    --repo-root . 2>&1
"""


def _install_precommit_hook(root: "str | None" = None) -> str:
    from pathlib import Path
    import stat

    base = Path(root) if root is not None else Path(".")
    git_hooks = base / ".git" / "hooks"
    if not git_hooks.is_dir():
        raise FileNotFoundError(".git/hooks not found — run from the repo root")
    hook_path = git_hooks / "pre-commit"
    hook_path.write_text(_PRECOMMIT_HOOK)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(hook_path.resolve())


def _install_prepush_hook(root: "str | None" = None) -> str:
    from pathlib import Path
    import stat

    base = Path(root) if root is not None else Path(".")
    git_hooks = base / ".git" / "hooks"
    if not git_hooks.is_dir():
        raise FileNotFoundError(".git/hooks not found — run from the repo root")
    hook_path = git_hooks / "pre-push"
    hook_path.write_text(_PRE_PUSH_HOOK)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(hook_path.resolve())


def cmd_hooks_install(args: argparse.Namespace) -> int:
    path = _settings_path(getattr(args, "global_scope", False), getattr(args, "project", False))
    all_harnesses = getattr(args, "all_harnesses", False)
    store = getattr(args, "store", None) or _default_hook_store()
    # --all-harnesses provisions the governed gate identically across Claude Code, Codex, and Gemini,
    # all feeding one evidence store, and drops the default policy — one command replaces hand-editing
    # three configs on every machine.
    _install_hooks(path, with_governance=getattr(args, "with_governance", False) or all_harnesses,
                   store=store if all_harnesses else None)
    print(f"CHP hooks installed in {path}")
    if all_harnesses:
        import shutil
        chp_bin = shutil.which("chp") or "chp"
        print(f"Gemini hooks installed in {_install_gemini_hooks(store, chp_bin)}")
        print(f"Codex hooks installed in {_install_codex_hooks(store, chp_bin)}")
        written = _write_default_policy()
        print(f"Default policy written to {written}" if written
              else "Policy already present — left as-is")
        print(f"Denials evidence store: {store}")
        print("Verify with: chp hook selftest")
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
