#!/usr/bin/env python3
"""Flywheel C2 — curate captured agent transcripts into an MLX-LoRA dataset.

Reads a JSONL corpus written by the harness/cockpit (CHP_CAPTURE_TRACES) — each
line `{"messages": [...], "meta": {...}}` — keeps the *good* runs, and writes
`train.jsonl` / `valid.jsonl` in mlx_lm's chat format (one `{"messages": [...]}`
per line) ready for `chp.adapters.mlx.finetune` (which runs `mlx_lm.lora`).

A run is kept when it (a) has a non-empty final assistant answer and (b) shows no
tool errors — a cheap proxy for "sanctioned + useful". Governance/provenance for
which runs are eligible can be tightened later by joining on the CHP correlation
id via `audit.query_invocations` (evidence is redacted, so the *content* lives
here in the transcript, the *signal* in the evidence).

    python curate.py ~/.chp/traces/harness.jsonl ./data --valid-frac 0.15
"""
from __future__ import annotations

import argparse
import json
import os
import random


def _content_text(m: dict) -> str:
    """AI SDK message content may be a string or a list of content parts."""
    c = m.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def _is_good(rec: dict) -> bool:
    msgs = rec.get("messages") or []
    if not msgs:
        return False
    # last assistant turn has real content
    last_assistant = next((m for m in reversed(msgs)
                           if m.get("role") == "assistant" and _content_text(m).strip()), None)
    if not last_assistant:
        return False
    # no tool error surfaced in any message
    blob = json.dumps(msgs).lower()
    if '"iserror":true' in blob or "tooldeniederror" in blob:
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Curate agent transcripts → MLX-LoRA dataset.")
    ap.add_argument("corpus", help="JSONL corpus from CHP_CAPTURE_TRACES.")
    ap.add_argument("out_dir", help="Output dir for train.jsonl / valid.jsonl.")
    ap.add_argument("--valid-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    kept: list[dict] = []
    total = 0
    with open(args.corpus) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _is_good(rec):
                kept.append({"messages": rec["messages"]})

    if not kept:
        print(f"No usable runs out of {total}. Capture more (CHP_CAPTURE_TRACES) before tuning.")
        return 1

    random.Random(args.seed).shuffle(kept)
    n_valid = max(1, int(len(kept) * args.valid_frac)) if len(kept) > 1 else 0
    valid, train = kept[:n_valid], kept[n_valid:]

    os.makedirs(args.out_dir, exist_ok=True)
    for name, rows in (("train", train), ("valid", valid)):
        with open(os.path.join(args.out_dir, f"{name}.jsonl"), "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
    print(f"curated {len(kept)}/{total} runs → {args.out_dir} (train={len(train)}, valid={len(valid)})")
    print("next: chp.adapters.mlx.finetune data=<out_dir> adapter_path=<lora_out> "
          "→ then mlx.start_server adapter_path=<lora_out>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
