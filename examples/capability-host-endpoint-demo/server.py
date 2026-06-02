#!/usr/bin/env python3
"""Serve the demo CHP host over HTTP."""

from __future__ import annotations

import argparse

from host_definition import build_demo_host

from chp_core import serve_http


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the CHP HTTP demo host.")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--store", default=".chp/demo-http-host.sqlite")
    args = parser.parse_args()

    host = build_demo_host(args.store)
    print(f"Serving CHP host {host.host_id} at http://{args.bind}:{args.port}")
    print("Routes: GET /host, GET /capabilities, POST /invoke, GET /replay/{correlation_id}")
    serve_http(host, bind=args.bind, port=args.port)


if __name__ == "__main__":
    main()
