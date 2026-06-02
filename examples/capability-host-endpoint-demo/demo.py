#!/usr/bin/env python3
"""Run the CHP HTTP endpoint demo end to end."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["demo", "endpoint"]))
