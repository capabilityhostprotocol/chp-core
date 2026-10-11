"""Shared pytest fixtures for the chp-core suite.

Hermetic host-auth environment: many tests spin up OPEN hosts / HTTP servers and make
UNAUTHENTICATED requests. If the process that launches pytest has host auth/config env set —
e.g. ``CHP_HOST_API_KEY`` injected from the macOS keychain into the chp-adapters MCP server that
runs the governed release / precommit capability — the test servers would demand auth and the
streaming / resilience / wire tests would 401 (observed: 35 spurious failures only under that
launcher, all green from a bare shell). Neutralize that ambient env once at session start so the
suite's result is independent of who launched it. A test that WANTS auth configured sets it with
``monkeypatch.setenv`` (function-scoped, still overrides and auto-restores within that test).
"""
from __future__ import annotations

import os

import pytest

_AMBIENT_HOST_AUTH_ENV = (
    "CHP_HOST_API_KEY",
    "CHP_HOST_API_KEYS",
    "CHP_HOST_TOKEN_KEYS",
    "CHP_HOST_APPROVER_KEYS",
    "CHP_HOST_ACTIVATION_AUDIENCE",
    "CHP_HOST_TRUSTED_PUBLISHERS",
    "CHP_HOST_REQUIRE_PINNED_APPROVER",
    "CHP_HOST_ACTIVATION_CONSUME_DB",
)


@pytest.fixture(scope="session", autouse=True)
def _hermetic_host_auth_env() -> None:
    for var in _AMBIENT_HOST_AUTH_ENV:
        os.environ.pop(var, None)
