#!/usr/bin/env python3
"""Flywheel — pull the shared corpus off the NAS into a local JSONL.

The harness/cockpit capture one transcript file per run to the NAS over the mesh
(CHP_CAPTURE_NAS_DIR, default /volume1/flywheel/traces). This pulls them all
(via the gateway, prefer=nas) and concatenates into a local corpus that
`curate.py` consumes — so any node can assemble the dataset before fine-tuning.

    export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
    python pull-nas.py /volume1/flywheel/traces ./corpus.jsonl
    python curate.py ./corpus.jsonl ./data
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request


def _invoke(gateway: str, key: str, cap: str, payload: dict) -> dict:
    body = json.dumps({"capability_id": cap, "payload": payload,
                       "metadata": {"prefer": "nas"}}).encode()
    req = urllib.request.Request(f"{gateway}/invoke", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    req.add_header("X-CHP-Key", key)
    r = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
    return r.get("data") or {} if r.get("outcome") == "success" else {}


def main() -> int:
    ap = argparse.ArgumentParser(description="Pull the NAS flywheel corpus to a local JSONL.")
    ap.add_argument("nas_dir", nargs="?", default="/volume1/flywheel/traces")
    ap.add_argument("out", nargs="?", default="./corpus.jsonl")
    ap.add_argument("--gateway", default=os.environ.get("CHP_GATEWAY", "http://127.0.0.1:8800"))
    args = ap.parse_args()
    key = os.environ.get("CHP_GATEWAY_KEY") or os.environ.get("CHP_HOST_API_KEY")
    if not key:
        print("Set CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)")
        return 2

    listing = _invoke(args.gateway, key, "chp.adapters.filesystem.list_directory", {"path": args.nas_dir})
    entries = listing.get("entries") or listing.get("files") or []
    names = [e.get("name") if isinstance(e, dict) else e for e in entries]
    names = [n for n in names if str(n).endswith(".jsonl")]

    n = 0
    with open(args.out, "w") as out:
        for name in names:
            d = _invoke(args.gateway, key, "chp.adapters.filesystem.read_file",
                       {"path": f"{args.nas_dir}/{name}"})
            content = (d.get("content") or "").strip()
            if content:
                out.write(content + "\n")
                n += 1
    print(f"pulled {n} transcript files from {args.nas_dir} → {args.out}")
    print(f"next: python curate.py {args.out} ./data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
