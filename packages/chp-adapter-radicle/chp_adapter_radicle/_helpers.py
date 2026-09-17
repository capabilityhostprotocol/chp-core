"""Shared parsers + constants for the Radicle adapter domain mixins."""
from __future__ import annotations

import re

_EMITS = ["radicle_request", "radicle_response", "radicle_error"]
_RAD_CLI_VERSION = "1.9.1"


def _parse_kv(output: str) -> dict[str, str]:
    """Parse ``Key   value`` lines (as emitted by ``rad inspect``, ``rad self``)."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower().rstrip(":")] = parts[1].strip()
    return result


def _parse_box_kv(output: str) -> dict[str, str]:
    """Parse the box-drawing table emitted by ``rad issue show``.

    Each content row looks like:  │ Key   value text   │
    Returns a dict with lowercase keys.
    """
    result: dict[str, str] = {}
    for line in output.splitlines():
        # Strip box chars and leading/trailing whitespace
        inner = line.strip().lstrip("│╭╰├╯").rstrip("│╮╯┤").strip()
        if not inner or inner.startswith("─") or inner.startswith("┤"):
            continue
        parts = inner.split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower().rstrip(":")
            # Only capture known header keys; skip body lines
            if key in ("title", "issue", "author", "labels", "status", "assignees"):
                result[key] = parts[1].strip()
    return result


def _parse_box_table(output: str) -> list[dict[str, str]]:
    """Parse the box-drawing table emitted by ``rad issue list`` / ``rad patch list``.

    Data rows have the form:  │ ●   <id>   <rest...>   │
    Returns list of dicts with at minimum ``id`` and ``title``.
    """
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        inner = line.strip()
        if not inner.startswith("│"):
            continue
        inner = inner.lstrip("│").rstrip("│").strip()
        # Skip header/separator rows (no ● marker or starts with ID header)
        if not inner.startswith("●"):
            continue
        inner = inner.lstrip("●").strip()
        # Split into fields by 2+ spaces
        fields = re.split(r"\s{2,}", inner)
        if len(fields) >= 2 and re.match(r"^[0-9a-f]{7,40}$", fields[0]):
            row: dict[str, str] = {"id": fields[0], "title": fields[1]}
            # fields: id, title, author, (you), labels, opened
            # Labels have no spaces; timestamps do ("17 hours ago")
            if len(fields) >= 5 and fields[4] and " " not in fields[4]:
                row["labels"] = fields[4]
            rows.append(row)
    return rows


def _parse_issue_table(output: str) -> list[dict]:
    """Parse ``rad issue list`` — fixed-width columns ID/Title/Author/Labels/Assignees/Opened.

    Slices each data row by the header column positions (robust to content width) and returns
    ``{id, title, labels: [...]}``. The Labels column is comma-separated.
    """
    lines = output.splitlines()
    header = next((ln for ln in lines if "ID" in ln and "Title" in ln and "Labels" in ln), None)
    if header is None:
        return []
    cols = ["ID", "Title", "Author", "Labels", "Assignees", "Opened"]
    pos = {c: header.find(c) for c in cols if header.find(c) >= 0}
    present = [c for c in cols if c in pos]
    rows: list[dict] = []
    for ln in lines:
        if "●" not in ln or not ln.lstrip().startswith("│"):
            continue
        cell: dict[str, str] = {}
        for i, c in enumerate(present):
            start = pos[c]
            end = pos[present[i + 1]] if i + 1 < len(present) else len(ln)
            cell[c.lower()] = ln[start:end].strip().rstrip("│").strip()
        iid = cell.get("id", "")
        if not re.match(r"^[0-9a-f]{7,40}$", iid):
            continue
        labels = [t.strip() for t in cell.get("labels", "").split(",") if t.strip()]
        rows.append({"id": iid, "title": cell.get("title", ""), "labels": labels})
    return rows


def _state_flag(state: str | None, valid: tuple[str, ...]) -> list[str]:
    """Convert a state string to the appropriate ``--<state>`` rad CLI flag.

    If *state* is None or not in *valid*, returns ``[]`` (CLI default applies).
    """
    if state and state in valid:
        return [f"--{state}"]
    return []


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
