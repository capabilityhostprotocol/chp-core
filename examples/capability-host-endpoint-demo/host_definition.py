"""Demo CHP host definition served over HTTP."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core.demo import (  # noqa: E402,F401
    build_demo_host,
    deploy_preview,
    search_information,
)
