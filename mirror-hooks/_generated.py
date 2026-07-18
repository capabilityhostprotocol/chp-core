"""Classify whether a repo-relative path is GENERATED content in the chp-core mirror.

chp-core contains ONLY what chp-dev publishes (scripts/sync-manifest.txt [sync]), so at the top level a
whole synced dir is generated. This mirrors that [sync] set at the top level; update it if the manifest
adds a new top-level published dir/file. Used by mirror-hooks/pre-commit to reject hand edits to the
mirror (edit chp-dev and sync instead) — the situation that forced --no-verify (rad:bd0c700).
"""
from __future__ import annotations

import sys

# ponytail: hardcoded to the manifest's TOP-LEVEL [sync] surface (stable; a new published top-level
# dir is rare). If that churns, read scripts/sync-manifest.txt instead — but the mirror doesn't carry
# the manifest today, and publishing it would leak the internal-dir names in its comments.
GENERATED_PREFIXES = (
    "spec/", "schemas/", "conformance/", "examples/", "packages/",
    "docs/", "registry/", "provenance/",
)
GENERATED_FILES = {
    "README.md", "LICENSE", "LICENSE-DOCS", "NOTICE",
    "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "SECURITY.md",
    "scripts/bootstrap-mac.sh", "scripts/bootstrap-linux.sh",
    "scripts/security-self-audit.py",
}


def is_generated(path: str) -> bool:
    return path in GENERATED_FILES or any(path.startswith(p) for p in GENERATED_PREFIXES)


def generated_among(paths) -> list[str]:
    return [p for p in paths if is_generated(p)]


def _selftest() -> None:
    assert is_generated("packages/python/chp_core/store.py")
    assert is_generated("spec/chp-v0.2.md")
    assert is_generated("docs/quickstart.md")
    assert is_generated("README.md")
    assert is_generated("scripts/security-self-audit.py")
    # NOT generated: mirror-native infra a maintainer may legitimately edit in chp-core
    assert not is_generated("mirror-hooks/pre-commit")
    assert not is_generated(".github/workflows/ci.yml")
    assert not is_generated("scripts/some-mirror-only-tool.sh")
    print("ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        staged = [ln.strip() for ln in sys.stdin if ln.strip()]
        print("\n".join(generated_among(staged)))
