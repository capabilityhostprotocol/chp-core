"""Stdlib HTTP server for the CHP dashboard."""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections import defaultdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .pages import (
    breakdown_page,
    error_page,
    session_detail_page,
    sessions_page,
    tree_page,
)

_DEFAULT_PORT = 8080


def _default_store() -> str:
    try:
        from chp_core.hooks import default_store_path
        return default_store_path()
    except Exception:
        return str(Path.home() / ".chp" / "claude-code-sessions.sqlite")


class _Handler(BaseHTTPRequestHandler):
    store_path: str = ""  # set in main()

    def log_message(self, fmt, *args):
        pass  # suppress default Apache-style logging

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        try:
            if path == "/":
                self._sessions()
            elif path == "/breakdown":
                self._breakdown()
            elif path.startswith("/api/sessions"):
                self._api_sessions()
            elif path.startswith("/api/breakdown"):
                self._api_breakdown()
            elif path.startswith("/session/") and path.endswith("/tree"):
                sid = path[len("/session/"):-len("/tree")]
                self._tree(sid)
            elif path.startswith("/session/"):
                sid = path[len("/session/"):]
                self._session_detail(sid)
            else:
                self._html(HTTPStatus.NOT_FOUND, error_page(404, f"Not found: {path}"))
        except Exception as exc:  # noqa: BLE001
            self._html(HTTPStatus.INTERNAL_SERVER_ERROR, error_page(500, str(exc)))

    # ── Route handlers ────────────────────────────────────────────────────────

    def _sessions(self):
        from chp_core.store import SQLiteEvidenceStore
        store = SQLiteEvidenceStore(self.store_path)
        try:
            events = list(reversed(store.query(capability_id="claude_code.session", limit=50)))
        finally:
            store.close()
        self._html(HTTPStatus.OK, sessions_page(events))

    def _session_detail(self, session_id: str):
        from chp_core.store import SQLiteEvidenceStore
        store = SQLiteEvidenceStore(self.store_path)
        try:
            events   = store.by_correlation(session_id)
            chain    = store.verify_chain(session_id)
            children = store.children_of(session_id)
        finally:
            store.close()
        if not events:
            self._html(HTTPStatus.NOT_FOUND, error_page(404, f"Session not found: {session_id}"))
            return
        self._html(HTTPStatus.OK, session_detail_page(session_id, events, chain.valid, children))

    def _tree(self, session_id: str):
        # Capture tree_view output as text
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from tools.chp_inspector.tree_view import render_tree
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            render_tree(session_id, self.store_path)
        finally:
            sys.stdout = old_stdout
        self._html(HTTPStatus.OK, tree_page(session_id, buf.getvalue().strip()))

    def _breakdown(self):
        from chp_core.store import SQLiteEvidenceStore
        store = SQLiteEvidenceStore(self.store_path)
        try:
            events = store.query()
        finally:
            store.close()
        counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for ev in events:
            cap = ev.get("capability_id") or "(none)"
            out = ev.get("outcome") or ev.get("event_type") or "?"
            counts[cap][out] += 1
        self._html(HTTPStatus.OK, breakdown_page(dict(counts)))

    def _api_sessions(self):
        from chp_core.store import SQLiteEvidenceStore
        store = SQLiteEvidenceStore(self.store_path)
        try:
            events = list(reversed(store.query(capability_id="claude_code.session", limit=50)))
        finally:
            store.close()
        self._json({"sessions": events})

    def _api_breakdown(self):
        from chp_core.store import SQLiteEvidenceStore
        store = SQLiteEvidenceStore(self.store_path)
        try:
            events = store.query()
        finally:
            store.close()
        counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for ev in events:
            cap = ev.get("capability_id") or "(none)"
            out = ev.get("outcome") or ev.get("event_type") or "?"
            counts[cap][out] += 1
        self._json({"breakdown": {k: dict(v) for k, v in counts.items()}})

    # ── Response helpers ──────────────────────────────────────────────────────

    def _html(self, status: HTTPStatus, body: str):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj: object):
        data = json.dumps(obj, default=str).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.chp_dashboard",
        description=f"CHP Dashboard v{__version__} — web UI for CHP session evidence.",
    )
    default_store = _default_store()
    parser.add_argument("--store", default=default_store, metavar="PATH",
                        help=f"SQLite evidence store (default: {default_store})")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, metavar="PORT",
                        help=f"HTTP port (default: {_DEFAULT_PORT})")
    parser.add_argument("--bind", default="127.0.0.1", metavar="ADDR",
                        help="Bind address (default: 127.0.0.1)")
    args = parser.parse_args()

    _Handler.store_path = args.store

    server = ThreadingHTTPServer((args.bind, args.port), _Handler)
    print(f"CHP Dashboard  →  http://{args.bind}:{args.port}/")
    print(f"Store: {args.store}")
    print("Press Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
