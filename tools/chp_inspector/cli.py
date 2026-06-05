"""CLI entry-point and argument parser for chp_inspector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _default_store() -> str:
    try:
        from chp_core.hooks import default_store_path
        return default_store_path()
    except Exception:
        return str(Path.home() / ".chp" / "claude-code-sessions.sqlite")


def _build_parser() -> argparse.ArgumentParser:
    default_store = _default_store()
    p = argparse.ArgumentParser(
        prog="python -m tools.chp_inspector",
        description="Inspect, query, and govern CHP session evidence.",
    )
    p.add_argument(
        "--store",
        default=default_store,
        metavar="PATH",
        help=f"SQLite evidence store (default: {default_store})",
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")

    # sessions
    s = sub.add_parser("sessions", help="List recent sessions.")
    s.add_argument("--limit", type=int, default=20, metavar="N")

    # show
    s = sub.add_parser("show", help="Rich summary for a session.")
    s.add_argument("session_id")

    # tree
    s = sub.add_parser("tree", help="Multi-agent session tree with chain status.")
    s.add_argument("session_id")
    s.add_argument("--depth", type=int, default=10, metavar="N")

    # query
    s = sub.add_parser("query", help="Filtered evidence query.")
    s.add_argument("--cap", dest="capability_id", default=None, metavar="CAP_ID")
    s.add_argument("--outcome", default=None)
    s.add_argument("--since", default=None, metavar="ISO_TS")
    s.add_argument("--until", default=None, metavar="ISO_TS")
    s.add_argument("--limit", type=int, default=None, metavar="N")

    # breakdown
    s = sub.add_parser("breakdown", help="Per-capability success/failure counts.")
    s.add_argument("--since", default=None, metavar="ISO_TS")

    # policy
    s = sub.add_parser("policy", help="Evaluate a policy file against stored evidence.")
    s.add_argument("session_id")
    s.add_argument("policy_file")

    # verify
    s = sub.add_parser("verify", help="Verify hash chain for a session.")
    s.add_argument("session_id")

    # diff
    s = sub.add_parser("diff", help="Compare two sessions side by side.")
    s.add_argument("session_a")
    s.add_argument("session_b")

    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    store_path = args.store

    if args.command == "sessions":
        from .session_view import list_sessions
        list_sessions(store_path, limit=args.limit)

    elif args.command == "show":
        from .session_view import show_session
        show_session(args.session_id, store_path)

    elif args.command == "verify":
        from .session_view import verify_session
        return verify_session(args.session_id, store_path)

    elif args.command == "tree":
        from .tree_view import render_tree
        render_tree(args.session_id, store_path, depth=args.depth)

    elif args.command == "query":
        from .query_view import run_query
        run_query(
            store_path,
            capability_id=args.capability_id,
            outcome=args.outcome,
            since=args.since,
            until=args.until,
            limit=args.limit,
        )

    elif args.command == "breakdown":
        from .query_view import capability_breakdown
        capability_breakdown(store_path, since=args.since)

    elif args.command == "policy":
        from .policy_check import policy_check_session
        return policy_check_session(args.session_id, store_path, args.policy_file)

    elif args.command == "diff":
        from .diff_view import diff_sessions
        diff_sessions(args.session_a, args.session_b, store_path)

    return 0
