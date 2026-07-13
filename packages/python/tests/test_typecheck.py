"""CI-parity type-check gate. Runs the EXACT mypy command the release pipeline
runs (release-preflight.sh / ci.yml) over chp_core, inside the pytest suite — so a
type regression (notably the recurring check_alignment same-name/different-type
collision, arcs 0022-0028) fails a normal `pytest` run at the desk instead of
surprising CI or the release sync. Skips cleanly if mypy is not installed."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]  # …/chp-dev
MYPY_ARGS = [
    "packages/python/chp_core",
    "--ignore-missing-imports",
    "--no-strict-optional",
    "--exclude", "/(tests|demo|__pycache__)/",
]


@pytest.mark.skipif(shutil.which("mypy") is None and
                    subprocess.run([sys.executable, "-c", "import mypy"],
                                   capture_output=True).returncode != 0,
                    reason="mypy not installed")
def test_chp_core_typechecks_ci_parity() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "mypy", *MYPY_ARGS],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        "CI-parity mypy found type errors in chp_core "
        "(often a check_alignment same-name/different-type collision — give each "
        "guard block a unique local name):\n" + (result.stdout or result.stderr)
    )
