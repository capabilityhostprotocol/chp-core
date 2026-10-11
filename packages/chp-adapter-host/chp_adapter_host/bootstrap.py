"""Dependency bootstrap: get a capability's SYSTEM prerequisites off the ground on any device.

Python deps ride the wheels (pip). This covers the layer pip can't: binaries (docker, runsc,
kata), devices (/dev/tpm0, /dev/kvm), OS packages (tpm2-tools), group memberships (tss, docker),
and services (ollama). A capability DECLARES its prereqs; this engine DETECTS what's present,
PLANS installs per-OS, and FAILS CLOSED honestly on what a device structurally cannot provide
(W4 on a Mac has no TPM — we say so, never pretend). The plan is pure given host facts, so it is
fully offline-testable; detection and execution are the only impure edges.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Prereq:
    name: str                               # "docker", "tpm2-tools", …
    kind: str                               # binary | device | os_package | group | service
    probe: str                              # binary name | device path | pkgbin | group | url
    unlocks: str                            # the capability feature it enables
    install: dict[str, str] = field(default_factory=dict)  # {pkg_manager: command}
    requires_facts: tuple[str, ...] = ()    # host-fact flags that must hold to be satisfiable (e.g. "kvm")
    hardware: bool = False                  # True = can't be installed; the device either has it or not


@dataclass(frozen=True)
class HostFacts:
    os: str                                 # linux | darwin | windows
    arch: str
    pkg_manager: str | None                 # apt | dnf | brew | winget | None
    binaries: frozenset[str] = frozenset()
    devices: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()    # the node user's group memberships
    flags: frozenset[str] = frozenset()     # capability flags, e.g. "kvm", "tpm"


@dataclass(frozen=True)
class Resolution:
    satisfied: list[str]
    to_install: list[tuple[str, str]]       # (prereq name, command to run)
    unsatisfiable: list[tuple[str, str]]    # (prereq name, honest reason)

    @property
    def ready(self) -> bool:
        """Ready iff nothing is left to install AND nothing is unsatisfiable (honest, not optimistic)."""
        return not self.to_install and not self.unsatisfiable


def _present(prereq: Prereq, facts: HostFacts) -> bool:
    if prereq.kind == "capability":
        return prereq.probe in facts.flags    # OS-neutral capability (virt, tpm, …) — NOT a device path
    if prereq.kind == "binary":
        return prereq.probe in facts.binaries
    if prereq.kind == "device":
        return prereq.probe in facts.devices
    if prereq.kind == "group":
        return prereq.probe in facts.groups
    if prereq.kind in ("os_package", "service"):
        return prereq.probe in facts.binaries  # probe = the binary the pkg/service provides
    return False


def resolve(prereqs: list[Prereq], facts: HostFacts) -> Resolution:
    """Pure: classify each prereq against host facts into satisfied / to-install / unsatisfiable."""
    satisfied, to_install, unsatisfiable = [], [], []
    for p in prereqs:
        if _present(p, facts):
            satisfied.append(p.name)
            continue
        missing_flag = next((f for f in p.requires_facts if f not in facts.flags), None)
        if p.hardware or missing_flag:
            reason = (f"requires host capability {missing_flag!r} which this device lacks"
                      if missing_flag else "hardware prerequisite absent on this device")
            unsatisfiable.append((p.name, f"{reason} — {p.unlocks} unavailable here (honest degrade)"))
            continue
        cmd = p.install.get(facts.pkg_manager or "")
        if cmd:
            to_install.append((p.name, cmd))
        else:
            unsatisfiable.append((p.name, f"no install recipe for {facts.pkg_manager or facts.os}"))
    return Resolution(satisfied, to_install, unsatisfiable)


def _detect_virt(os_name: str) -> bool:
    """Hardware-virtualization capability present? Detected PER-OS — never a hardcoded Linux device
    path. linux: /dev/kvm | darwin: Hypervisor.framework (sysctl kern.hv_support) | windows:
    Win32_ComputerSystem.HypervisorPresent. Unknown OS → False (honest, not optimistic)."""
    if os_name == "linux":
        return os.path.exists("/dev/kvm")
    if os_name == "darwin":
        try:
            r = subprocess.run(["sysctl", "-n", "kern.hv_support"],
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip() == "1"
        except Exception:  # noqa: BLE001
            return False
    if os_name == "windows":
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"],
                               capture_output=True, text=True, timeout=20)
            return r.stdout.strip().lower() == "true"
        except Exception:  # noqa: BLE001
            return False
    return False


def _detect_tpm(os_name: str) -> bool:
    """TPM 2.0 capability present? linux: /dev/tpm[rm]0 | windows: TBS (Get-Tpm .TpmPresent). macOS
    has no TPM 2.0 (the Secure Enclave is NOT a TPM) → honest False, never pretended."""
    if os_name == "linux":
        return os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
    if os_name == "windows":
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                "(Get-Tpm).TpmPresent"],
                               capture_output=True, text=True, timeout=20)
            return r.stdout.strip().lower() == "true"
        except Exception:  # noqa: BLE001
            return False
    return False


def detect_host() -> HostFacts:
    """Impure: gather this host's facts. (In a live deploy, run on the target node.) Hardware
    capabilities (virt, tpm) are detected per-OS by the helpers above — no device path is hardcoded
    as the universal truth, so Windows/macOS/Linux are each detected on their own terms."""
    sysname = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system(), platform.system().lower())
    pm = ("apt" if shutil.which("apt-get") else "dnf" if shutil.which("dnf")
          else "brew" if shutil.which("brew") else "winget" if shutil.which("winget") else None)
    probes = ("docker", "runsc", "kata-runtime", "tpm2_quote", "ollama")
    binaries = frozenset(b for b in probes if shutil.which(b))
    devices = frozenset(d for d in ("/dev/tpm0", "/dev/tpmrm0", "/dev/kvm") if os.path.exists(d))
    groups: set[str] = set()
    try:
        groups = set(subprocess.run(["id", "-Gn"], capture_output=True, text=True, timeout=5).stdout.split())
    except Exception:  # noqa: BLE001 — `id` is POSIX-only; on Windows groups stay empty (fine)
        pass
    flags = set()
    if _detect_virt(sysname):
        flags.add("virt")        # OS-neutral: KVM | Hypervisor.framework | Hyper-V
    if _detect_tpm(sysname):
        flags.add("tpm")
    return HostFacts(sysname, platform.machine(), pm, binaries, devices, frozenset(groups), frozenset(flags))


# ── Built-in GENERIC prerequisites (container substrate + inference) ──────────────────────────────
# Only generic, product-agnostic substrate lives here. DOMAIN-specific hardware prerequisites (e.g.
# CHP Safety's W4 TPM + own-kernel microVM) are NOT hardcoded in the host — the owning adapter
# DECLARES them via the `chp.prereqs` entry point and the engine discovers them (adapter-first).
# Docker from its OFFICIAL SIGNED repository — NOT `curl https://get.docker.com | sh` (unpinned,
# unverified remote-code-into-root-shell). apt: a GPG keyring under /etc/apt/keyrings + the
# download.docker.com repo (arch + distro derived; mirrors the gVisor keyring pattern below). dnf:
# config-manager + the signed docker-ce.repo. Both verify Docker's GPG key before install.
_APT_DOCKER = (
    "( set -e; . /etc/os-release; sudo install -m 0755 -d /etc/apt/keyrings; "
    "curl -fsSL https://download.docker.com/linux/$ID/gpg | sudo gpg --dearmor "
    "-o /etc/apt/keyrings/docker.gpg; sudo chmod a+r /etc/apt/keyrings/docker.gpg; "
    "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] "
    "https://download.docker.com/linux/$ID $VERSION_CODENAME stable\" | sudo tee "
    "/etc/apt/sources.list.d/docker.list; sudo apt-get update && sudo apt-get install -y "
    "docker-ce docker-ce-cli containerd.io )")
_DNF_DOCKER = (
    "( set -e; . /etc/os-release; sudo dnf -y install dnf-plugins-core; "
    "sudo dnf config-manager --add-repo https://download.docker.com/linux/$ID/docker-ce.repo; "
    "sudo dnf install -y docker-ce docker-ce-cli containerd.io )")
DOCKER = Prereq("docker", "binary", "docker", "shared-kernel cells (OpenShell/OpenCell)",
                install={"apt": _APT_DOCKER, "dnf": _DNF_DOCKER,
                         "brew": "brew install --cask docker",
                         "winget": "winget install -e --id Docker.DockerDesktop"})
GVISOR = Prereq("gvisor", "binary", "runsc", "gVisor sandbox-kernel boundary",
                install={"apt": "( set -e; curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor "
                                "-o /usr/share/keyrings/gvisor-archive-keyring.gpg; echo \"deb [arch=$(dpkg "
                                "--print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg]"
                                " https://storage.googleapis.com/gvisor/releases release main\" | sudo tee "
                                "/etc/apt/sources.list.d/gvisor.list; sudo apt-get update && sudo apt-get install "
                                "-y runsc )"})  # apt repo multi-arch → arch derived; linux-only (else honest-degrade)
# ollama ships no signed apt/dnf repo — install.sh over TLS is the documented method; residual
# supply-chain trust remains (pin OLLAMA_VERSION / review the script to reduce it). Unlike Docker +
# gVisor (both keyring-verified above), this one can't yet be GPG-pinned.
OLLAMA = Prereq("ollama", "service", "ollama", "sovereign on-device LLM inference (ollama backend)",
                install={"apt": "curl -fsSL https://ollama.com/install.sh | sh",
                         "dnf": "curl -fsSL https://ollama.com/install.sh | sh",
                         "brew": "brew install ollama",
                         "winget": "winget install -e --id Ollama.Ollama"})


# ── Adapter-declared prerequisites: discovery (adapter-first) ─────────────────────────────────────
CHP_PREREQS_GROUP = "chp.prereqs"


def _prereq_from_dict(d: dict) -> tuple[str, Prereq]:
    """Parse one DECLARED prereq (plain data from a `chp.prereqs` entry point) → (tier_key, Prereq).
    Plain-data so a declaring adapter needs no import of this engine (loose coupling)."""
    return d.get("tier", "containment"), Prereq(
        name=d["name"], kind=d["kind"], probe=d["probe"], unlocks=d.get("unlocks", d["name"]),
        install=dict(d.get("install", {})), requires_facts=tuple(d.get("requires_facts", ())),
        hardware=bool(d.get("hardware", False)))


def discover_prereqs(group: str = CHP_PREREQS_GROUP) -> dict[str, list[Prereq]]:
    """Discover installed adapters' declared system prerequisites, grouped by tier key. Each entry
    point loads a zero-arg callable returning list[dict]. A broken/absent declarer is skipped — the
    generic built-ins still provision node/containment, so the host is never crippled."""
    from importlib.metadata import entry_points
    by_tier: dict[str, list[Prereq]] = {}
    for ep in entry_points(group=group):
        try:
            declared = ep.load()() or []
        except Exception:  # noqa: BLE001 — a bad declarer must never break planning
            continue
        for d in declared:
            try:
                tier, p = _prereq_from_dict(d)
            except (KeyError, TypeError):
                continue
            by_tier.setdefault(tier, []).append(p)
    return by_tier


@dataclass(frozen=True)
class Tier:
    key: str
    label: str
    prereqs: list[Prereq]


# node ⊂ containment ⊂ assurance. Built-ins carry only the GENERIC container substrate; hardware
# runtime-assurance prereqs (KVM/Kata/TPM) arrive from chp-adapter-safety's `chp.prereqs` declaration.
TIERS: list[Tier] = [
    Tier("node", "Governed host + the adapters you name (no system extras)", []),
    Tier("containment", "+ shared-kernel cells (Docker, gVisor)", [DOCKER, GVISOR]),
    Tier("assurance", "+ hardware runtime assurance: own-kernel microVM + W4 TPM "
                      "(declared by chp-adapter-safety)", [DOCKER, GVISOR]),
]
_TIER_INDEX = {t.key: i for i, t in enumerate(TIERS)}


def _tier_prereqs(tier_key: str) -> list[Prereq]:
    """Cumulative prereqs for a tier = built-in (generic) ∪ adapter-declared, up to & including this
    tier. A declared prereq OWNS its name (it overrides a built-in of the same name), so the adapter
    that owns a substrate is authoritative for how it is provisioned."""
    if tier_key not in _TIER_INDEX:
        raise ValueError(f"unknown tier {tier_key!r}; one of {[t.key for t in TIERS]}")
    cumulative = [t.key for t in TIERS[:_TIER_INDEX[tier_key] + 1]]
    merged: dict[str, Prereq] = {}
    for t in TIERS[:_TIER_INDEX[tier_key] + 1]:
        for p in t.prereqs:
            merged[p.name] = p
    discovered = discover_prereqs()
    for tk in cumulative:
        for p in discovered.get(tk, []):
            merged[p.name] = p
    return list(merged.values())


def plan_tier(tier_key: str, facts: HostFacts, *, with_inference: bool = False) -> Resolution:
    """Resolve the cumulative prereqs for an install TIER (built-in ∪ adapter-declared) against the
    host, + optional inference backend."""
    prereqs = _tier_prereqs(tier_key)
    if with_inference:
        prereqs.append(OLLAMA)
    return resolve(prereqs, facts)


def render_plan(tier_key: str, facts: HostFacts, *, with_inference: bool = False) -> str:
    """Human-readable PURE plan for a tier on these host facts (no installs, no evidence). Shared by
    the module CLI and `chp-server onboard --plan` so the feasibility preview has one rendering."""
    r = plan_tier(tier_key, facts, with_inference=with_inference)
    lines = [f"host: {facts.os}/{facts.arch}  pkg={facts.pkg_manager}  tier={tier_key}"
             + ("  +inference" if with_inference else ""),
             "  satisfied    : " + (", ".join(r.satisfied) or "-")]
    lines += [f"  will install : {n}  ->  {c}" for n, c in r.to_install]
    lines += [f"  cannot (honest): {n}  — {w}" for n, w in r.unsatisfiable]
    lines.append(f"  ready: {r.ready}")
    return "\n".join(lines)


# ── Hardened executor (evidence is emitted via the host's ctx.emit, not a hand-rolled ledger) ────
# The install process is self-evidencing so it can be inspected per environment: each phase is
# emitted through the host's ctx.emit (chp.adapters.host.bootstrap) into the host's signed,
# SHA256-chained ExecutionEvidence store — replayable via `chp replay`. No secrets: steps are
# package installs; output tails are bounded. Pure resolver + hardened executor live here; the
# capability wires the evidence.

@dataclass(frozen=True)
class StepResult:
    name: str
    command: str
    exit_code: int
    duration_ms: int
    stdout_tail: str
    stderr_tail: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _run_step(name: str, command: str, *, timeout: int = 1800) -> StepResult:
    """Run one prereq install step. Never raises — a failure is captured, not fatal (so one bad step
    doesn't abort the whole bootstrap; the record + post-verify tell the honest story)."""
    t0 = time.monotonic()
    try:
        p = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=timeout)
        ms = int((time.monotonic() - t0) * 1000)
        return StepResult(name, command, p.returncode, ms, p.stdout[-1000:], p.stderr[-1000:])
    except subprocess.TimeoutExpired:
        return StepResult(name, command, 124, int((time.monotonic() - t0) * 1000), "",
                          f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001 — record any launch failure as a failed step
        return StepResult(name, command, 1, int((time.monotonic() - t0) * 1000), "",
                          f"{type(exc).__name__}: {exc}"[:1000])


def _decide_outcome(dry_run: bool, planned: list[str], step_oks: list[bool],
                    still_missing: list[str]) -> str:
    """Honest outcome: 'ok' ONLY when every planned prereq is verified present after install
    (re-detected — a zero exit code is not proof). 'partial' when some remain; 'failed' when every
    step errored; 'nothing-to-do' when nothing was planned; 'planned' for a dry run."""
    if dry_run:
        return "planned"
    if not planned:
        return "nothing-to-do"
    if not still_missing:
        return "ok"
    if step_oks and not any(step_oks):
        return "failed"
    return "partial"


def build_record(facts: HostFacts, res: "Resolution", steps: list[StepResult],
                 still_missing: list[str], *, tier: str, inference: bool, outcome: str) -> dict:
    """The install record (host facts, plan, per-step results, post-verify, outcome). Returned to the
    caller AND emitted as CHP evidence by the host.bootstrap capability — NOT written to a parallel
    hand-rolled ledger; the host's signed, SHA256-chained ExecutionEvidence store is the record."""
    planned = [n for n, _ in res.to_install]
    return {
        "kind": "chp-install-record/v0.1", "ts": round(time.time(), 3),
        "host": {"os": facts.os, "arch": facts.arch, "pkg_manager": facts.pkg_manager,
                 "binaries": sorted(facts.binaries), "devices": sorted(facts.devices),
                 "groups": sorted(facts.groups), "flags": sorted(facts.flags)},
        "tier": tier, "inference": inference,
        "satisfied_before": res.satisfied,
        "planned": planned,
        "unsatisfiable": [{"name": n, "reason": w} for n, w in res.unsatisfiable],
        "steps": [{"name": s.name, "command": s.command, "exit_code": s.exit_code,
                   "duration_ms": s.duration_ms, "ok": s.ok,
                   "stdout_tail": s.stdout_tail, "stderr_tail": s.stderr_tail} for s in steps],
        "verified_after": {"now_satisfied": [n for n in planned if n not in still_missing],
                           "still_missing": still_missing},
        "outcome": outcome,
    }


def execute(tier: str, *, inference: bool = False, dry_run: bool = False,
            facts: HostFacts | None = None, timeout: int = 1800, emit=None) -> dict:
    """Plan → (unless dry_run) run each install step, hardened → RE-DETECT to verify the installs
    actually took (exit 0 is not proof) → honest outcome. ``emit(event_type, data)`` is invoked for
    each phase (detect/plan/step/verify/complete); pass a host's ``ctx.emit`` so the install is
    recorded as CHP ExecutionEvidence (signed, chained, replayable) — there is NO hand-rolled ledger.
    Returns the install record dict."""
    def _emit(event: str, data: dict) -> None:
        if emit is not None:
            try:
                emit(event, data)
            except Exception:  # noqa: BLE001 — evidence emission must never break the install itself
                pass

    facts = facts or detect_host()
    _emit("bootstrap_detected", {"os": facts.os, "arch": facts.arch,
                                 "pkg_manager": facts.pkg_manager, "flags": sorted(facts.flags)})
    res = plan_tier(tier, facts, with_inference=inference)
    planned = [n for n, _ in res.to_install]
    _emit("bootstrap_planned", {"tier": tier, "inference": inference, "planned": planned,
                                "unsatisfiable": [n for n, _ in res.unsatisfiable]})
    steps: list[StepResult] = []
    if not dry_run:
        for name, cmd in res.to_install:
            s = _run_step(name, cmd, timeout=timeout)
            steps.append(s)
            _emit("bootstrap_step", {"name": s.name, "exit_code": s.exit_code, "ok": s.ok,
                                     "duration_ms": s.duration_ms, "stderr_tail": s.stderr_tail[-300:]})
    after = detect_host() if (steps and not dry_run) else facts
    still_missing = [n for n, _ in plan_tier(tier, after, with_inference=inference).to_install]
    outcome = _decide_outcome(dry_run, planned, [s.ok for s in steps], still_missing)
    _emit("bootstrap_verified", {"now_satisfied": [n for n in planned if n not in still_missing],
                                 "still_missing": still_missing})
    _emit("bootstrap_complete", {"tier": tier, "outcome": outcome})
    return build_record(facts, res, steps, still_missing, tier=tier, inference=inference, outcome=outcome)


def _main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="chp-bootstrap",
                                 description="Detect, plan, and (optionally) execute a node's system "
                                             "prerequisites for an install tier — with evidence.")
    ap.add_argument("--tier", default="node", choices=[t.key for t in TIERS])
    ap.add_argument("--inference", action="store_true", help="also plan a sovereign LLM backend (ollama)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--execute", action="store_true",
                    help="run the plan (unevidenced standalone; prefer `chp-server onboard`, which "
                         "runs this as a governed cap that records CHP evidence)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    if a.execute:
        rec = execute(a.tier, inference=a.inference, dry_run=a.dry_run)
        if a.json:
            print(json.dumps(rec))
        else:
            print(f"install outcome: {rec['outcome']}  (tier={a.tier}"
                  + ("  +inference" if a.inference else "") + ")")
            for s in rec["steps"]:
                print(f"  {'ok ' if s['ok'] else 'FAIL'} {s['name']}  (exit {s['exit_code']}, {s['duration_ms']}ms)")
            if rec["verified_after"]["still_missing"]:
                print("  still missing after install:", ", ".join(rec["verified_after"]["still_missing"]))
        return 0 if rec["outcome"] in ("ok", "nothing-to-do", "planned") else 1

    facts = detect_host()
    if a.json:
        r = plan_tier(a.tier, facts, with_inference=a.inference)
        print(json.dumps({"os": facts.os, "arch": facts.arch, "pkg_manager": facts.pkg_manager,
                          "tier": a.tier, "inference": a.inference, "ready": r.ready,
                          "satisfied": r.satisfied, "to_install": r.to_install,
                          "unsatisfiable": r.unsatisfiable}))
        return 0
    print(render_plan(a.tier, facts, with_inference=a.inference))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
