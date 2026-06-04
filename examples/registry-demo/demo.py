"""Local registry demo (v0.2.9).

Shows how to manage the ~/.chp/registry.json adapter registry using both
the Python API and the CLI.

Run:
    python examples/registry-demo/demo.py
"""

import json
import tempfile
from pathlib import Path

from chp_core.registry import RegistryEntry, add_entry, load_registry, remove_entry, save_registry


def example_registry_api(reg_path: str) -> None:
    print("=== Example 1: Registry API ===")

    # Add adapters
    add_entry(RegistryEntry(
        id="codex",
        package="chp-codex",
        version=">=1.0.0",
        tags=["agentic", "openai"],
    ), path=reg_path)

    add_entry(RegistryEntry(
        id="gemini_cli",
        package="chp-gemini-cli",
        version=">=1.0.0",
        tags=["agentic", "google"],
    ), path=reg_path)

    # List
    entries = load_registry(reg_path)
    print(f"  {len(entries)} adapters registered:")
    for e in entries:
        print(f"    {e.id:20s}  pkg={e.package}  enabled={e.enabled}")

    # Update (idempotent add)
    add_entry(RegistryEntry(id="codex", package="chp-codex", version=">=2.0.0"), path=reg_path)
    updated = next(e for e in load_registry(reg_path) if e.id == "codex")
    print(f"\n  Updated codex version: {updated.version}")

    # Remove
    removed = remove_entry("gemini_cli", path=reg_path)
    print(f"  Removed gemini_cli: {removed}")
    print(f"  Remaining: {[e.id for e in load_registry(reg_path)]}")


def example_registry_file_format(reg_path: str) -> None:
    print("\n=== Example 2: Registry file format ===")
    content = Path(reg_path).read_text()
    print(content)


def example_cli_workflow() -> None:
    print("=== Example 3: CLI commands (printed, not executed) ===")
    cmds = [
        "chp registry list",
        "chp registry add codex --package chp-codex --version '>=1.0.0' --tag agentic",
        "chp registry add gemini_cli --package chp-gemini-cli --tag agentic --tag google",
        "chp registry remove gemini_cli",
        "chp registry status",
    ]
    for cmd in cmds:
        print(f"  $ {cmd}")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        reg_path = str(Path(tmpdir) / "registry.json")
        example_registry_api(reg_path)
        example_registry_file_format(reg_path)
        example_cli_workflow()
