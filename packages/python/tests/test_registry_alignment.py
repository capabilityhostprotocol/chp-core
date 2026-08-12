"""Tests for the subset-safe registry alignment check (§2B).

Guards two properties:
  * a package with no registry entry FAILS (catches an unregistered adapter)
  * a registry entry with no package PASSES (subset sync, e.g. chp-core, must
    not false-positive — only package->entry is asserted, never the reverse)
"""

from __future__ import annotations

import json

from chp_core.protocol_checks import check_registry_alignment


def _layout(root, *, packages, registered):
    (root / "registry").mkdir(parents=True, exist_ok=True)
    (root / "packages").mkdir(parents=True, exist_ok=True)
    (root / "registry" / "adapters.json").write_text(
        json.dumps({
            "categories": ["network", "platform"],
            "official": [{"id": r, "pypi": r, "category": "network",
                          "description": "x", "status": "certified", "tier": 1}
                         for r in registered],
            "community": [],
        })
    )
    for pkg in packages:
        (root / "packages" / pkg).mkdir(parents=True, exist_ok=True)


def _passed(result):
    return result["checks"][0]["passed"]


def test_unregistered_package_fails(tmp_path):
    _layout(tmp_path, packages=["chp-adapter-http", "chp-adapter-new"],
            registered=["chp-adapter-http"])
    result = check_registry_alignment(tmp_path)
    assert _passed(result) is False
    assert "chp-adapter-new" in result["checks"][0]["details"]["unregistered"]


def test_registry_superset_passes(tmp_path):
    # chp-core case: more registry entries than packages — must not fail.
    _layout(tmp_path, packages=["chp-adapter-http"],
            registered=["chp-adapter-http", "chp-adapter-vllm", "chp-adapter-scout"])
    assert _passed(check_registry_alignment(tmp_path)) is True


def test_missing_registry_skips(tmp_path):
    (tmp_path / "packages").mkdir()
    result = check_registry_alignment(tmp_path)
    assert result.get("skipped") is True
    assert result["passed"] is True


def _manifest(root, *, public):
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    body = "[sync]\n# a comment\npackages/python/\n" + "".join(
        f"packages/{p}/\n" for p in public
    )
    (root / "scripts" / "sync-manifest.txt").write_text(body)


def test_private_adapter_is_out_of_scope(tmp_path):
    """registry/adapters.json is a PUBLIC catalog. An adapter the manifest keeps
    private must not force a choice between a red gate and disclosing it."""
    _layout(tmp_path, packages=["chp-adapter-http", "chp-adapter-secret"],
            registered=["chp-adapter-http"])
    _manifest(tmp_path, public=["chp-adapter-http"])
    result = check_registry_alignment(tmp_path)
    assert _passed(result) is True
    assert result["checks"][0]["details"]["scope"] == "public"


def test_public_adapter_still_must_be_registered(tmp_path):
    """The exemption is scoped to private packages — it must not swallow a real
    unregistered PUBLIC adapter."""
    _layout(tmp_path, packages=["chp-adapter-http", "chp-adapter-new"],
            registered=["chp-adapter-http"])
    _manifest(tmp_path, public=["chp-adapter-http", "chp-adapter-new"])
    result = check_registry_alignment(tmp_path)
    assert _passed(result) is False
    assert "chp-adapter-new" in result["checks"][0]["details"]["unregistered"]


def test_no_manifest_falls_back_to_all_packages(tmp_path):
    """The public mirror has no manifest — every package present is in scope."""
    _layout(tmp_path, packages=["chp-adapter-http", "chp-adapter-new"],
            registered=["chp-adapter-http"])
    result = check_registry_alignment(tmp_path)
    assert _passed(result) is False
    assert result["checks"][0]["details"]["scope"] == "all packages"
