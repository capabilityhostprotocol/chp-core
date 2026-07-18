"""The crypto/evidence self-audit runs green in CI — a standing regression that CHP's
signed-evidence guarantees fail closed under adversarial attack. See
``scripts/security-self-audit.py`` for the attacks. If this fails, a security guarantee
has a hole; read the printed per-check detail."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_AUDIT = Path(__file__).resolve().parents[3] / "scripts" / "security-self-audit.py"


def test_all_security_guarantees_fail_closed() -> None:
    spec = importlib.util.spec_from_file_location("_chp_security_self_audit", _AUDIT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["_chp_security_self_audit"] = module
    spec.loader.exec_module(module)

    results = []
    for _claim, name, fn in module._CHECKS:  # noqa: SLF001
        try:
            fn()
            results.append((name, "PASS", ""))
        except Exception as exc:  # noqa: BLE001
            results.append((name, "FAIL", f"{type(exc).__name__}: {exc}"))

    holes = [r for r in results if r[1] != "PASS"]
    assert not holes, "security guarantees with holes: " + "; ".join(
        f"{n} ({d})" for n, _s, d in holes)
    assert len(results) >= 7  # guard against the suite silently shrinking
