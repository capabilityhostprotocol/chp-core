"""Producer-independent OpenCell containment check — self-contained (promoted from chp-safety).

Given an OBSERVATION of a running cell (e.g. from an independent `docker inspect`, NOT the control
plane that created it) and the Envelope-compiled plan `constraints`, decide whether the cell satisfies
the required containment invariants. Pure + fail-closed: any missing or true failure condition ⇒ not
satisfied. The honest verifier half — it runs independently of whatever produced the cell.
"""

from __future__ import annotations

from typing import Any, Mapping


def verify_cell_against_plan(
    inspect_obs: Mapping[str, Any],
    constraints: Mapping[str, Any],
    *,
    boundary_class: str = "",
) -> tuple[bool, list[str]]:
    """Return (satisfied, failures). `constraints` are the compiled plan's structural constraints
    (network / read_only / docker_runtime); `inspect_obs` is an independent observation of the live
    cell (guest_network_device / non_root_user / guest_credentials / read_only_rootfs / effect_channel
    / channel_authenticated / network_mode / runtime)."""
    failures: list[str] = []
    if inspect_obs.get("guest_network_device") is not False:
        failures.append("guest has a network device (vNIC present or unknown)")
    if inspect_obs.get("non_root_user") is not True:
        failures.append("guest not running as a non-root user")
    creds = list(inspect_obs.get("guest_credentials") or [])
    if creds:
        failures.append("guest-visible credentials present: " + ",".join(map(str, creds)))
    if constraints.get("read_only") and inspect_obs.get("read_only_rootfs") is False:
        failures.append("rootfs is not read-only")
    if inspect_obs.get("effect_channel") and not inspect_obs.get("channel_authenticated"):
        failures.append("effect channel not authenticated")
    expected_net = constraints.get("network", "none")
    if inspect_obs.get("network_mode") not in (expected_net, None):
        failures.append(f"network_mode {inspect_obs.get('network_mode')!r} != expected {expected_net!r}")
    expected_runtime = constraints.get("docker_runtime")
    if expected_runtime and inspect_obs.get("runtime") not in (expected_runtime, None):
        failures.append(f"runtime {inspect_obs.get('runtime')!r} != expected {expected_runtime!r} "
                        f"(boundary {boundary_class})")
    return (not failures), failures
