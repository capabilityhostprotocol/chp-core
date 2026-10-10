"""CHP Safety's SYSTEM prerequisites — declared here because safety OWNS its runtime-assurance
substrate (adapter-first). The generic bootstrap engine (chp-adapter-host) discovers these via the
`chp.prereqs` entry point and merges them into the install plan; they are plain data so this module
imports nothing from the engine (loose coupling).

Each dict:  name, kind (capability|binary|device|os_package|group|service), probe (what detection
looks for — for `capability`, an OS-neutral host-fact flag like `virt`/`tpm`, NOT a device path),
unlocks (the assurance it enables), install (per-package-manager command), requires_facts (host-fact
flags that must hold to be satisfiable), hardware (True = can't be installed — the host has the
capability or not), tier (which install tier it belongs to).

These are the hardware runtime-assurance prerequisites: own-kernel microVM (hardware virtualization
capability + Kata) and the W4 TPM witness (TPM capability + tpm2-tools + the `tss` group). Hardware is
declared as an ABSTRACT CAPABILITY (`virt`, `tpm`) so the engine can detect it per-OS (KVM /
Hypervisor.framework / Hyper-V; Linux TPM device / Windows TBS) rather than this declaration
hardcoding a Linux device path. Docker/gVisor (the shared-kernel cell substrate) stay GENERIC in the
host engine; only CHP Safety's W4/microVM ladder is owned here. See chp-safety docs/NUC_SETUP.md +
docs/W4_RUNBOOK.md.
"""
from __future__ import annotations


def declare() -> list[dict]:
    """Return CHP Safety's declared system prerequisites (consumed by chp.adapters.host.bootstrap)."""
    return [
        {"name": "kata", "kind": "binary", "probe": "kata-runtime",
         "unlocks": "own-kernel microVM boundary (qualified-microVM OpenCell/OpenShell)",
         "install": {"apt": "# install kata-go-static tarball to /opt/kata "
                             "(see chp-safety docs/NUC_SETUP.md §B)"},
         "requires_facts": ["virt"], "tier": "assurance"},
        # Abstract hardware CAPABILITIES — detected per-OS by the engine (KVM | Hypervisor.framework |
        # Hyper-V; Linux TPM device | Windows TBS). No device path is hardcoded here.
        {"name": "hw-virt", "kind": "capability", "probe": "virt",
         "unlocks": "hardware virtualization for own-kernel microVM",
         "hardware": True, "tier": "assurance"},
        {"name": "tpm", "kind": "capability", "probe": "tpm",
         "unlocks": "W4 hardware-attested witness",
         "hardware": True, "tier": "assurance"},
        {"name": "tpm2-tools", "kind": "os_package", "probe": "tpm2_quote",
         "unlocks": "W4 TPM quote generation",
         "install": {"apt": "sudo apt-get update && sudo apt-get install -y tpm2-tools",
                     "dnf": "sudo dnf install -y tpm2-tools"},
         "requires_facts": ["tpm"], "tier": "assurance"},
        {"name": "tss-group", "kind": "group", "probe": "tss",
         "unlocks": "node user's access to the TPM device",
         "install": {"apt": "sudo usermod -aG tss \"$USER\"  # re-login / cycle the user manager after",
                     "dnf": "sudo usermod -aG tss \"$USER\""},
         "requires_facts": ["tpm"], "tier": "assurance"},
    ]
