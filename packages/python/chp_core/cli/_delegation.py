"""CHP CLI delegation handoff chain commands."""

from __future__ import annotations

import argparse

from ._core import _resolve_store, print_json

_DELEGATION_EVENT_TYPES = {
    "delegation_created",
    "delegation_accepted",
    "delegation_completed",
    "delegation_rejected",
    "delegation_reassigned",
}


def cmd_delegation_show(args: argparse.Namespace) -> int:
    from ..store import SQLiteEvidenceStore

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.by_correlation(args.correlation_id)
    finally:
        store.close()

    chain = [e for e in events if e.get("event_type") in _DELEGATION_EVENT_TYPES]

    if not chain:
        print(f"No delegation events found for correlation: {args.correlation_id}")
        return 1

    print_json({"correlation_id": args.correlation_id, "chain": chain})
    return 0
