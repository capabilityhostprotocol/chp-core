"""A practical semver-range subset for capability-version negotiation (chp-v0.2.md
§1.1, proposal 0028). Both reference implementations (Python here, TS
`semver.ts`) parse ranges identically so a caller's ``requested_capability_version``
resolves the same everywhere.

Supported: exact ``1.0.0``; caret ``^1.2.0`` (``>=1.2.0 <2.0.0``); tilde ``~1.2.3``
(``>=1.2.3 <1.3.0``); comparators ``>= > <= < =``; x-ranges ``1.x`` / ``1`` /
``1.2.x``; ``*`` (any); space = AND. Versions compare as ``(major, minor, patch)``
integer tuples (pre-release / build tags are stripped — deferred).
"""

from __future__ import annotations

from typing import Tuple

Version = Tuple[int, int, int]


def parse_version(v: str) -> Version:
    """``"1.2.3"`` → ``(1, 2, 3)``; missing parts are 0; a pre-release/build tag is
    dropped. A non-numeric part is treated as 0 (lenient)."""
    core = str(v).strip().split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    out = [0, 0, 0]
    for i in range(3):
        if i < len(parts) and parts[i].isdigit():
            out[i] = int(parts[i])
    return (out[0], out[1], out[2])


def _cmp(a: Version, b: Version) -> int:
    return (a > b) - (a < b)


def _bump(v: Version, idx: int) -> Version:
    """The exclusive upper bound: increment component ``idx``, zero those below."""
    parts = list(v)
    parts[idx] += 1
    for j in range(idx + 1, 3):
        parts[j] = 0
    return (parts[0], parts[1], parts[2])


def _satisfies_one(version: Version, comp: str) -> bool:
    comp = comp.strip()
    if comp in ("", "*", "x", "X"):
        return True
    if comp.startswith("^"):
        base = parse_version(comp[1:])
        # ^1.2.3 → >=1.2.3 <2.0.0; ^0.2.3 → <0.3.0; ^0.0.3 → <0.0.4 (semver 0.x).
        if base[0] > 0:
            upper = _bump((base[0], 0, 0), 0)
        elif base[1] > 0:
            upper = _bump((0, base[1], 0), 1)
        else:
            upper = _bump((0, 0, base[2]), 2)
        return _cmp(version, base) >= 0 and _cmp(version, upper) < 0
    if comp.startswith("~"):
        base = parse_version(comp[1:])
        return _cmp(version, base) >= 0 and _cmp(version, _bump((base[0], base[1], 0), 1)) < 0
    for op in (">=", "<=", ">", "<", "="):
        if comp.startswith(op):
            base = parse_version(comp[len(op):])
            c = _cmp(version, base)
            return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
    # An x-range or a bare/partial version: 1.x / 1 / 1.2.x / 1.2 / 1.2.3.
    tokens = comp.replace("*", "x").replace("X", "x").split(".")
    if "x" in tokens:
        i = tokens.index("x")
        prefix = [int(t) for t in tokens[:i]]
        if not prefix:
            return True
        pad = (prefix + [0, 0, 0])
        lower: Version = (pad[0], pad[1], pad[2])
        upper = _bump(lower, len(prefix) - 1)  # 1.x → <2.0.0; 1.2.x → <1.3.0
        return _cmp(version, lower) >= 0 and _cmp(version, upper) < 0
    if len(tokens) < 3:  # a partial exact "1" / "1.2" means that prefix, any below
        prefix = [int(t) for t in tokens if t.isdigit()]
        pad = (prefix + [0, 0, 0])
        plower: Version = (pad[0], pad[1], pad[2])
        upper = _bump(plower, len(prefix) - 1)
        return _cmp(version, plower) >= 0 and _cmp(version, upper) < 0
    return version == parse_version(comp)  # exact "1.2.3"


def version_satisfies(version: str, spec: str) -> bool:
    """True iff ``version`` satisfies the range ``spec`` (space-separated ANDs)."""
    v = parse_version(version)
    return all(_satisfies_one(v, c) for c in str(spec).split() if c.strip())


def best_satisfying(versions: list[str], spec: str) -> str | None:
    """The highest of ``versions`` that satisfies ``spec``, or None."""
    ok = [v for v in versions if version_satisfies(v, spec)]
    return max(ok, key=parse_version) if ok else None


def _selfcheck() -> None:
    """Runnable: ``python -m chp_core.semver``."""
    assert version_satisfies("1.2.3", "1.2.3")
    assert not version_satisfies("1.2.4", "1.2.3")
    assert version_satisfies("1.5.0", "^1.2.0") and not version_satisfies("2.0.0", "^1.2.0")
    assert version_satisfies("1.2.9", "~1.2.3") and not version_satisfies("1.3.0", "~1.2.3")
    assert version_satisfies("1.5.0", ">=1.0 <2") and not version_satisfies("2.0.0", ">=1.0 <2")
    assert version_satisfies("1.9.9", "1.x") and not version_satisfies("2.0.0", "1.x")
    assert version_satisfies("1.2.9", "1.2.x") and not version_satisfies("1.3.0", "1.2.x")
    assert version_satisfies("3.1.4", "*") and version_satisfies("0.0.1", "")
    assert version_satisfies("0.2.5", "^0.2.0") and not version_satisfies("0.3.0", "^0.2.0")
    assert best_satisfying(["1.0.0", "1.5.0", "2.0.0"], "^1.0.0") == "1.5.0"
    assert best_satisfying(["2.0.0", "3.0.0"], "^1.0.0") is None
    print("semver self-check OK")


if __name__ == "__main__":
    _selfcheck()
