"""Tests for the dependency-bootstrap engine + the governed chp.adapters.host.bootstrap capability.

The engine's resolver/planner is PURE (offline-testable); the capability wraps the hardened executor
and records every phase as signed, SHA256-chained CHP ExecutionEvidence — there is NO hand-rolled
ledger. The built-ins here are GENERIC substrate (docker/gVisor/ollama); domain hardware prereqs are
adapter-DECLARED and discovered, so these tests isolate discovery to stay deterministic regardless of
which adapters happen to be installed. chp-adapter-safety's own suite tests its declaration.
"""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, register_adapter

from chp_adapter_host import HostAdapter
from chp_adapter_host import bootstrap as b

_REAL_DISCOVER = b.discover_prereqs      # captured before the autouse isolation fixture patches it


@pytest.fixture(autouse=True)
def _isolate_discovery(monkeypatch):
    """Default adapter-prereq discovery to EMPTY so the engine tests see only the generic built-ins,
    regardless of what's installed in the environment. Discovery tests override this explicitly."""
    monkeypatch.setattr(b, "discover_prereqs", lambda group=b.CHP_PREREQS_GROUP: {})


def _names(pairs):
    return {n for n, _ in pairs}


def _cmds(res):
    return {n: c for n, c in res.to_install}


# ── pure resolver / tiers (generic built-ins) ─────────────────────────────────────────────────────
def test_node_tier_has_no_prereqs():
    r = b.plan_tier("node", b.HostFacts("linux", "x86_64", "apt"))
    assert r.ready and not r.to_install


def test_containment_plan_is_generic_substrate():
    r = b.plan_tier("containment", b.HostFacts("linux", "x86_64", "apt"))
    assert _names(r.to_install) == {"docker", "gvisor"}


def test_containment_ready_when_substrate_present():
    full = b.HostFacts("linux", "x86_64", "apt", binaries=frozenset({"docker", "runsc"}))
    r = b.plan_tier("containment", full)
    assert r.ready and set(r.satisfied) == {"docker", "gvisor"}


def test_macos_degrades_gvisor_honestly():
    r = b.plan_tier("containment", b.HostFacts("darwin", "arm64", "brew",
                                               binaries=frozenset({"docker"})))
    assert r.satisfied == ["docker"]
    assert _names(r.unsatisfiable) == {"gvisor"}      # gVisor is linux-only; never pretended on a Mac
    assert not r.ready


def test_tiers_are_cumulative():
    fresh = b.HostFacts("linux", "x86_64", "apt")
    node, cont, assr = (b.plan_tier(t, fresh) for t in ("node", "containment", "assurance"))
    assert node.ready and not node.to_install                       # node needs no system extras
    assert _names(cont.to_install) == {"docker", "gvisor"}
    assert _names(cont.to_install).issubset(_names(assr.to_install))  # cumulative


def test_inference_add_on_plans_ollama():
    r = b.plan_tier("node", b.HostFacts("linux", "x86_64", "apt"), with_inference=True)
    assert "ollama" in _names(r.to_install)


def test_unknown_tier_raises():
    with pytest.raises(ValueError):
        b.plan_tier("quantum", b.HostFacts("linux", "x86_64", "apt"))


# ── adapter-first prereq discovery ─────────────────────────────────────────────────────────────────
def test_prereq_from_dict_parses_tier_and_defaults():
    tier, p = b._prereq_from_dict({"name": "x", "kind": "binary", "probe": "x", "tier": "assurance"})
    assert tier == "assurance" and p.name == "x" and p.unlocks == "x" and p.install == {}
    assert p.requires_facts == () and p.hardware is False


def test_discover_prereqs_skips_broken_declarer(monkeypatch):
    class _EP:
        def __init__(self, fn): self._fn = fn
        def load(self): return self._fn
    good = lambda: [{"name": "tpm", "kind": "device", "probe": "/dev/tpm0", "hardware": True,
                     "tier": "assurance"}]
    def bad():
        raise RuntimeError("declarer exploded")
    import importlib.metadata as md
    monkeypatch.setattr(md, "entry_points", lambda group=None: [_EP(bad), _EP(good)])
    disc = _REAL_DISCOVER()                                          # the real function, not isolated
    assert [p.name for p in disc.get("assurance", [])] == ["tpm"]    # good kept, bad skipped


def test_discovered_prereqs_merge_into_their_tier_only(monkeypatch):
    monkeypatch.setattr(b, "discover_prereqs", lambda group=b.CHP_PREREQS_GROUP: {
        "assurance": [b.Prereq("tpm", "capability", "tpm", "W4 witness", hardware=True)]})
    fresh = b.HostFacts("linux", "x86_64", "apt")                   # no 'tpm' capability flag
    cont = b.plan_tier("containment", fresh)
    assr = b.plan_tier("assurance", fresh)
    assert "tpm" not in _names(cont.to_install) | _names(cont.unsatisfiable)   # not in containment
    assert "tpm" in _names(assr.unsatisfiable)                     # capability absent → honest degrade


def test_capability_prereq_satisfied_by_flag():
    cap = b.Prereq("hw-virt", "capability", "virt", "hardware virtualization", hardware=True)
    has = b.HostFacts("linux", "x86_64", "apt", flags=frozenset({"virt"}))
    nope = b.HostFacts("linux", "x86_64", "apt")
    assert b.resolve([cap], has).ready                              # flag present → satisfied
    assert _names(b.resolve([cap], nope).unsatisfiable) == {"hw-virt"}   # absent → honest degrade


# ── OS-aware hardware detection (no hardcoded device path is the universal truth) ─────────────────
def test_detect_virt_per_os(monkeypatch):
    monkeypatch.setattr(b.os.path, "exists", lambda p: p == "/dev/kvm")
    assert b._detect_virt("linux") is True                         # linux: /dev/kvm
    monkeypatch.setattr(b.os.path, "exists", lambda p: False)
    assert b._detect_virt("linux") is False

    def _run(cmd, **kw):
        out = "1" if cmd[:2] == ["sysctl", "-n"] else ""
        return type("R", (), {"stdout": out})()
    monkeypatch.setattr(b.subprocess, "run", _run)
    assert b._detect_virt("darwin") is True                        # darwin: kern.hv_support == 1

    monkeypatch.setattr(b.subprocess, "run",
                        lambda cmd, **kw: type("R", (), {"stdout": "True\n"})())
    assert b._detect_virt("windows") is True                       # windows: HypervisorPresent


def test_detect_tpm_macos_is_honestly_false(monkeypatch):
    # macOS has no TPM 2.0 (Secure Enclave is not a TPM) — never pretended, regardless of anything
    monkeypatch.setattr(b.os.path, "exists", lambda p: True)
    assert b._detect_tpm("darwin") is False


def test_detect_tpm_windows_uses_tbs(monkeypatch):
    monkeypatch.setattr(b.subprocess, "run",
                        lambda cmd, **kw: type("R", (), {"stdout": "True\n"})())
    assert b._detect_tpm("windows") is True                        # windows: Get-Tpm .TpmPresent


def test_declared_prereq_overrides_builtin_by_name(monkeypatch):
    custom = b.Prereq("docker", "binary", "docker", "custom", install={"apt": "my-docker-install"})
    monkeypatch.setattr(b, "discover_prereqs",
                        lambda group=b.CHP_PREREQS_GROUP: {"containment": [custom]})
    r = b.plan_tier("containment", b.HostFacts("linux", "x86_64", "apt"))
    assert _cmds(r)["docker"] == "my-docker-install"               # the declarer owns the name


# ── hardened executor ────────────────────────────────────────────────────────────────────────────
def test_decide_outcome_is_honest_about_verified_installs():
    assert b._decide_outcome(False, ["docker"], [True], ["docker"]) == "partial"
    assert b._decide_outcome(False, ["docker"], [True], []) == "ok"
    assert b._decide_outcome(False, ["docker"], [False], ["docker"]) == "failed"
    assert b._decide_outcome(False, [], [], []) == "nothing-to-do"
    assert b._decide_outcome(True, ["docker"], [], ["docker"]) == "planned"


def test_run_step_captures_success_and_failure():
    ok = b._run_step("echo", "echo hello")
    assert ok.ok and ok.exit_code == 0 and "hello" in ok.stdout_tail
    bad = b._run_step("fail", "echo oops 1>&2; exit 7")
    assert not bad.ok and bad.exit_code == 7 and "oops" in bad.stderr_tail


def test_execute_dry_run_emits_every_phase_and_plans_only():
    events: list[tuple[str, dict]] = []
    mac = b.HostFacts("darwin", "arm64", "brew", binaries=frozenset({"docker"}))
    rec = b.execute("containment", facts=mac, dry_run=True, emit=lambda e, d: events.append((e, d)))
    assert rec["outcome"] == "planned"
    assert [e for e, _ in events] == [
        "bootstrap_detected", "bootstrap_planned", "bootstrap_verified", "bootstrap_complete"]
    assert rec["steps"] == []                                      # dry run installs nothing
    assert {u["name"] for u in rec["unsatisfiable"]} >= {"gvisor"}  # honest degrade carried in record


def test_execute_emit_failure_never_breaks_the_run():
    def boom(_e, _d):
        raise RuntimeError("evidence sink down")
    rec = b.execute("node", facts=b.HostFacts("linux", "x86_64", "apt"), dry_run=True, emit=boom)
    assert rec["outcome"] in ("planned", "nothing-to-do")


# ── the governed capability records CHP evidence ──────────────────────────────────────────────────
def _host():
    h = LocalCapabilityHost("test-bootstrap")
    register_adapter(h, HostAdapter())
    return h


def test_bootstrap_capability_records_chp_evidence_dry_run():
    h = _host()
    result = h.invoke("chp.adapters.host.bootstrap",
                      {"tier": "containment", "dry_run": True}, correlation_id="bs-1")
    assert result.outcome == "success"
    assert result.data["outcome"] == "planned"
    assert result.evidence_ids                                     # recorded as CHP evidence
    chain = h.store.verify_chain("bs-1")
    assert getattr(chain, "valid", chain)                          # signed + chained, intact


def test_bootstrap_capability_rejects_unknown_tier():
    result = _host().invoke("chp.adapters.host.bootstrap", {"tier": "quantum", "dry_run": True})
    assert result.outcome != "success"


# ── cross-OS plan matrix (generic containment substrate — durable proof for OSes not run live) ────
def test_plan_matrix_debian_apt():
    cmds = _cmds(b.plan_tier("containment", b.HostFacts("linux", "x86_64", "apt")))
    assert "download.docker.com" in cmds["docker"]                 # signed repo, not curl|sh
    assert "runsc" in cmds["gvisor"]                               # gVisor installable on apt


def test_plan_matrix_fedora_dnf():
    r = b.plan_tier("containment", b.HostFacts("linux", "x86_64", "dnf"))
    cmds, cannot = _cmds(r), {n: w for n, w in r.unsatisfiable}
    assert "download.docker.com" in cmds["docker"]                 # signed dnf repo, not curl|sh
    assert "no install recipe for dnf" in cannot["gvisor"]         # gVisor dnf recipe is a known gap


def test_plan_matrix_macos_brew():
    r = b.plan_tier("containment", b.HostFacts("darwin", "arm64", "brew"))
    cmds, cannot = _cmds(r), {n: w for n, w in r.unsatisfiable}
    assert cmds["docker"] == "brew install --cask docker"
    assert "no install recipe for brew" in cannot["gvisor"]


def test_plan_matrix_windows_winget():
    r = b.plan_tier("containment", b.HostFacts("windows", "AMD64", "winget"), with_inference=True)
    cmds, cannot = _cmds(r), {n: w for n, w in r.unsatisfiable}
    assert cmds["docker"] == "winget install -e --id Docker.DockerDesktop"
    assert cmds["ollama"] == "winget install -e --id Ollama.Ollama"
    assert "no install recipe for winget" in cannot["gvisor"]


def test_docker_recipe_is_signed_repo_not_curl_pipe_sh():
    """Regression: Docker must install from its GPG-signed repo, never `curl get.docker.com | sh`
    (unpinned remote-code-into-root-shell on every onboarding node)."""
    apt = b.DOCKER.install["apt"]
    dnf = b.DOCKER.install["dnf"]
    assert "get.docker.com" not in apt and "get.docker.com" not in dnf
    assert "download.docker.com" in apt and "signed-by=/etc/apt/keyrings/docker.gpg" in apt
    assert "download.docker.com" in dnf and "docker-ce.repo" in dnf


def test_gvisor_apt_recipe_is_architecture_derived():
    """Regression: the gVisor apt repo line must derive arch at run time (arm64 Linux too), never
    hardcode amd64 — that would wire the wrong-arch repo on an arm64 host."""
    apt = b.GVISOR.install["apt"]
    assert "dpkg --print-architecture" in apt
    assert "arch=amd64" not in apt


def test_render_plan_is_pure_and_honest():
    txt = b.render_plan("containment", b.HostFacts("darwin", "arm64", "brew"))
    assert "tier=containment" in txt
    assert "will install :" in txt and "cannot (honest):" in txt   # both sides shown
    assert "ready: False" in txt                                   # Mac can't reach full containment
