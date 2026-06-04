"""Tests for v0.2.9 local registry."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from chp_core.registry import RegistryEntry, add_entry, load_registry, remove_entry, save_registry

_PACKAGES_DIR = str(Path(__file__).resolve().parents[1])


# ---------------------------------------------------------------------------
# Core registry functions
# ---------------------------------------------------------------------------

def test_load_registry_from_file(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    save_registry(
        [RegistryEntry(id="codex", package="chp-codex", version=">=1.0.0", tags=["agentic"])],
        path=reg_path,
    )
    entries = load_registry(reg_path)
    assert len(entries) == 1
    assert entries[0].id == "codex"
    assert entries[0].package == "chp-codex"
    assert "agentic" in entries[0].tags


def test_load_registry_returns_empty_when_missing(tmp_path) -> None:
    entries = load_registry(str(tmp_path / "nonexistent.json"))
    assert entries == []


def test_save_and_reload_registry(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    entries = [
        RegistryEntry(id="codex", package="chp-codex"),
        RegistryEntry(id="gemini_cli", package="chp-gemini-cli", enabled=False),
    ]
    save_registry(entries, path=reg_path)
    loaded = load_registry(reg_path)
    assert len(loaded) == 2
    gemini = next(e for e in loaded if e.id == "gemini_cli")
    assert gemini.enabled is False


def test_add_entry_idempotent(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    entry = RegistryEntry(id="codex", package="chp-codex")
    add_entry(entry, path=reg_path)
    add_entry(entry, path=reg_path)  # second add should not duplicate
    loaded = load_registry(reg_path)
    assert len([e for e in loaded if e.id == "codex"]) == 1


def test_add_entry_updates_existing(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    add_entry(RegistryEntry(id="codex", package="old-pkg"), path=reg_path)
    add_entry(RegistryEntry(id="codex", package="new-pkg"), path=reg_path)
    loaded = load_registry(reg_path)
    assert loaded[0].package == "new-pkg"


def test_remove_entry_returns_true_when_found(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    add_entry(RegistryEntry(id="codex"), path=reg_path)
    removed = remove_entry("codex", path=reg_path)
    assert removed is True
    assert load_registry(reg_path) == []


def test_remove_entry_returns_false_when_missing(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    removed = remove_entry("nonexistent", path=reg_path)
    assert removed is False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_cli(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "chp_core.cli"] + cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _PACKAGES_DIR},
    )


def test_registry_list_cli_exits_0(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    result = _run_cli(["registry", "list", "--registry", reg_path])
    assert result.returncode == 0
    assert json.loads(result.stdout) == []


def test_registry_add_cli_creates_entry(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    result = _run_cli(["registry", "add", "codex", "--package", "chp-codex", "--registry", reg_path])
    assert result.returncode == 0
    entries = load_registry(reg_path)
    assert len(entries) == 1
    assert entries[0].id == "codex"


def test_registry_remove_cli_removes_entry(tmp_path) -> None:
    reg_path = str(tmp_path / "registry.json")
    add_entry(RegistryEntry(id="codex"), path=reg_path)
    result = _run_cli(["registry", "remove", "codex", "--registry", reg_path])
    assert result.returncode == 0
    assert load_registry(reg_path) == []
