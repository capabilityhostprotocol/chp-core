"""Shared helpers for local CHP development checks."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .types import JSON


def add_check(checks: list[JSON], name: str, passed: bool, details: JSON) -> None:
    checks.append(
        {
            "name": name,
            "passed": passed,
            "details": details,
        }
    )


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path) -> JSON:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_check_name(path: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", path).strip("_")


def preview_text(value: str | bytes, limit: int = 1200) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if len(value) <= limit:
        return value
    return value[-limit:]
