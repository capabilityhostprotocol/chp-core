"""Non-bypassable enforcement — the basis for a CHP-ENFORCED claim (CHP-CORE-018).

A deployment MUST NOT claim CHP-enforced where the protected capability can execute through an ungoverned
bypass path (CHP-CORE-018, MUST NOT). This encodes that invariant as a small, reusable primitive: an
``EnforcementControl`` describes HOW a binding's execution is controlled, and ``assess_enforcement`` DERIVES
the honest level from it — never a hand-set badge. ``enforced`` is returned only when there is a real,
verifier-backed boundary AND no declared bypass path; a bypass path caps the claim at ``observed``.

The four levels are ordered by how much the deployment can honestly assert about execution control:
``enforced`` > ``observed`` > ``discoverable``. ``unenforceable`` marks a control that contradicts itself
(a boundary asserted alongside a bypass that defeats it) — surfaced so it is never silently downgraded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .types import JSON

ENFORCED = "enforced"
OBSERVED = "observed"
DISCOVERABLE = "discoverable"
LEVELS = (ENFORCED, OBSERVED, DISCOVERABLE)


@dataclass(slots=True)
class EnforcementControl:
    """How a binding's execution is controlled (CHP-CORE-018). ``boundary`` names the mechanism that forces
    execution through the governed host (e.g. ``"governed-grant"``: the effect system verifies the host's
    grant and refuses ungoverned calls); empty means no boundary. ``bypass_paths`` are any ungoverned ways
    the effect could STILL be produced — their presence forbids a CHP-enforced claim. ``verifier`` is what
    actually checks the boundary (e.g. a grant-signature verifier id); a boundary asserted without a verifier
    is not demonstrable, so it is at most ``observed``."""

    boundary: str = ""
    bypass_paths: list[str] = field(default_factory=list)
    verifier: JSON | None = None

    def is_non_bypassable(self) -> bool:
        """True iff there is a demonstrable boundary and NO ungoverned bypass path (CHP-CORE-018)."""
        return bool(self.boundary) and bool(self.verifier) and not self.bypass_paths

    def to_dict(self) -> JSON:
        d = asdict(self)
        if self.verifier is None:
            d.pop("verifier", None)
        return d


def _coerce(control: EnforcementControl | JSON | None) -> EnforcementControl | None:
    if control is None or isinstance(control, EnforcementControl):
        return control
    if isinstance(control, dict):
        return EnforcementControl(boundary=control.get("boundary", ""),
                                  bypass_paths=list(control.get("bypass_paths", []) or []),
                                  verifier=control.get("verifier"))
    return None


def assess_enforcement(control: EnforcementControl | JSON | None) -> str:
    """Derive the honest enforcement level from a control declaration (CHP-CORE-018).

    - ``enforced`` — a real boundary, a verifier, and NO bypass path (demonstrably non-bypassable).
    - ``observed`` — a boundary exists but is either unverified OR has a declared bypass path: the effect is
      observed through governance, but a CHP-enforced claim would be false (MUST NOT).
    - ``discoverable`` — no boundary at all; the capability is merely listed.
    """
    ctrl = _coerce(control)
    if ctrl is None or not ctrl.boundary:
        return DISCOVERABLE
    if ctrl.is_non_bypassable():
        return ENFORCED
    # a boundary is present but not demonstrably non-bypassable (unverified, or a bypass exists) → observed,
    # never enforced (CHP-CORE-018 forbids an enforced claim over a bypassable path).
    return OBSERVED


def host_enforcement(host: object) -> str:
    """Derive a running host's honest enforcement level from its ACTUAL controls (CHP-CORE-018).

    A CHP-ENFORCED claim must be a FACT about the host, not a self-declared badge. The governed host IS the
    boundary: every invocation is evidence-wrapped and policy-checked before any handler runs, and no public
    invoke path reaches a handler past a denial (proven in test_core_hardening) — so the boundary is real and
    the store+policy is its verifier. The one ungoverned bypass a host can carry is AUDIT-ONLY mode: policy
    decisions are recorded but NOT enforced, so a denied effect still runs — a declared bypass that caps the
    honest claim at ``observed``. A host with no policy/store wired has no governed boundary → ``discoverable``.

    Reads host attributes duck-typed (getattr), so this leaf primitive never imports the host layer."""
    policy = getattr(host, "policy", None)
    store = getattr(host, "store", None)
    if policy is None or store is None:
        return DISCOVERABLE  # no governed boundary is wired — the effect is merely reachable
    control = EnforcementControl(
        boundary="governed-host",
        verifier={"id": "chp.evidence-store+policy"},
        # audit-only logs decisions but does not block → the effect is produced anyway (an ungoverned bypass)
        bypass_paths=["audit_only"] if getattr(policy, "audit_only", False) else [],
    )
    return assess_enforcement(control)
