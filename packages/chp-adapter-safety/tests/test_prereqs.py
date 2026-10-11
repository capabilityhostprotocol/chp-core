"""chp-adapter-safety OWNS its runtime-assurance substrate prerequisites (adapter-first). This checks
the declaration itself, and — when the generic engine (chp-adapter-host) is installed — that the
engine discovers + merges it so `onboard --tier assurance` plans safety's hardware prereqs."""

from __future__ import annotations

import pytest

from chp_adapter_safety import prereqs


def test_declare_returns_the_hardware_assurance_substrate():
    decls = prereqs.declare()
    by_name = {d["name"]: d for d in decls}
    assert set(by_name) == {"kata", "hw-virt", "tpm", "tpm2-tools", "tss-group"}
    # all are assurance-tier (W4 / own-kernel microVM), never containment
    assert all(d["tier"] == "assurance" for d in decls)
    # hardware is an ABSTRACT CAPABILITY (OS-neutral flag), not a hardcoded /dev path
    assert by_name["hw-virt"]["kind"] == "capability" and by_name["hw-virt"]["probe"] == "virt"
    assert by_name["tpm"]["kind"] == "capability" and by_name["tpm"]["probe"] == "tpm"
    assert "/dev/" not in str(decls)                               # no device path hardcoded
    # the capabilities can't be installed; the host has them or not
    assert by_name["hw-virt"]["hardware"] is True and by_name["tpm"]["hardware"] is True
    # kata needs the virtualization capability (OS-neutral), not "kvm"
    assert by_name["kata"]["requires_facts"] == ["virt"]
    # tpm2-tools has a dnf recipe (RHEL/Fedora W4), gated on the tpm fact
    assert "dnf" in by_name["tpm2-tools"]["install"]
    assert by_name["tpm2-tools"]["requires_facts"] == ["tpm"]


def test_declaration_is_plain_data_no_engine_import():
    # loose coupling: the declaration must be JSON-ish plain data (no Prereq/engine objects)
    import json
    json.dumps(prereqs.declare())


def test_engine_discovers_and_merges_safety_prereqs():
    """With chp-adapter-safety installed, the engine's assurance plan includes safety's hardware
    prereqs. On a bare-metal linux host (KVM+TPM present) they become real install steps; on a host
    without the hardware they honestly degrade — never silently dropped."""
    pytest.importorskip("chp_adapter_host", reason="generic engine not installed")
    from chp_adapter_host import bootstrap as b

    # discovery must surface safety's declaration under the assurance tier
    discovered = b.discover_prereqs()
    assert {p.name for p in discovered.get("assurance", [])} >= {"kata", "hw-virt", "tpm",
                                                                 "tpm2-tools", "tss-group"}

    # a capable node with the virt+tpm CAPABILITIES (OS-neutral flags — the engine sets these per-OS)
    # → the hardware prereqs become install/satisfied, NOT unsatisfiable; docker/gvisor ride along.
    capable = b.HostFacts("linux", "x86_64", "apt", flags=frozenset({"virt", "tpm"}))
    r = b.plan_tier("assurance", capable)
    planned = {n for n, _ in r.to_install}
    assert {"tpm2-tools", "tss-group"}.issubset(planned)       # installable with TPM present
    assert "hw-virt" in r.satisfied and "tpm" in r.satisfied   # capabilities detected
