"""Deployment environment — the protocol's canonical dev/test/pilot/prod tiers.

ONE definition, consumed across the stack: chp-platform's ``ControlPlane``, chp-home's deploy
channels, and — stamped into ``CorrelationContext`` — every governed invocation's evidence, so an
evidence record is provably attributed to the environment it ran in. The active environment for a
process comes from ``CHP_ENV`` (default ``dev``); a prod host sets ``CHP_ENV=prod``.

Dependency-free (stdlib only), like the rest of the protocol core.
"""

from __future__ import annotations

import os

# Ordered least → most production-like. ``pilot`` = a real-but-limited production slice.
ENVIRONMENTS: tuple[str, ...] = ("dev", "test", "pilot", "prod")
DEFAULT_ENVIRONMENT = "dev"
ENV_VAR = "CHP_ENV"


def validate_environment(name: str) -> str:
    """Return ``name`` if it is a known environment, else raise — the single validation point
    (chp-platform's ControlPlane raised its own copy of this)."""
    if name not in ENVIRONMENTS:
        raise ValueError(f"unknown environment {name!r} (expected one of {ENVIRONMENTS})")
    return name


def current_environment() -> str:
    """The active environment for this process: ``$CHP_ENV`` (validated) or ``dev``. An invalid
    ``CHP_ENV`` raises rather than silently running as the wrong tier."""
    return validate_environment(os.environ.get(ENV_VAR, DEFAULT_ENVIRONMENT))
