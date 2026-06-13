#!/usr/bin/env python3
"""Serve the local chp-adapter-* host over HTTP for end-to-end testing.

    python server.py --port 8765

Routes (from chp_core.serve_http):
    GET  /health
    GET  /capabilities
    GET  /host
    POST /invoke              {"capability_id": "...", "payload": {...}}
    GET  /replay/{correlation_id}
"""

from __future__ import annotations

import argparse

from host_definition import DEFAULT_STORE, build_local_adapter_host

from chp_core import serve_http


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local CHP adapter host.")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--store", default=DEFAULT_STORE)
    args = parser.parse_args()

    host = build_local_adapter_host(args.store)
    print(f"\nServing CHP host {host.host_id} at http://{args.bind}:{args.port}")
    print("Routes: GET /capabilities, POST /invoke, GET /replay/{correlation_id}\n")
    serve_http(host, bind=args.bind, port=args.port)


if __name__ == "__main__":
    main()
