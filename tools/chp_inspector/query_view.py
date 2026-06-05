"""Evidence querying and capability breakdown views."""

from __future__ import annotations

from collections import defaultdict


def run_query(
    store_path: str,
    *,
    capability_id: str | None = None,
    outcome: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int | None = None,
) -> None:
    """Print filtered evidence events as compact one-liners."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.query(
            capability_id=capability_id,
            outcome=outcome,
            since=since,
            until=until,
            limit=limit,
        )
    finally:
        store.close()

    if not events:
        print("No events matched.")
        return

    print(f"\n{'SEQ':>5}  {'TYPE':<24}  {'CAPABILITY':<40}  {'OUTCOME':<10}  TIMESTAMP")
    print("-" * 110)
    for ev in events:
        seq  = ev.get("sequence", "?")
        typ  = (ev.get("event_type") or "")[:24]
        cap  = (ev.get("capability_id") or "")[:40]
        out  = (ev.get("outcome") or "")[:10]
        ts   = (ev.get("timestamp") or "")[:19].replace("T", " ")
        print(f"{str(seq):>5}  {typ:<24}  {cap:<40}  {out:<10}  {ts}")

    print(f"\n{len(events)} event(s) returned.")


def capability_breakdown(store_path: str, since: str | None = None) -> None:
    """Print per-capability success/failure/denied counts."""
    from chp_core.store import SQLiteEvidenceStore

    store = SQLiteEvidenceStore(store_path)
    try:
        kwargs: dict = {}
        if since is not None:
            kwargs["since"] = since
        events = store.query(**kwargs)
    finally:
        store.close()

    if not events:
        print("No events found.")
        return

    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for ev in events:
        cap     = ev.get("capability_id") or "(none)"
        outcome = ev.get("outcome") or ev.get("event_type") or "?"
        counts[cap][outcome] += 1

    cols = ["success", "failure", "denied"]
    hdr_cap = f"{'CAPABILITY':<44}"
    hdr_cols = "  ".join(f"{c:>8}" for c in cols)
    other_h  = f"  {'OTHER':>8}"
    print(f"\n{hdr_cap}  {hdr_cols}{other_h}")
    print("-" * (44 + 2 + len(hdr_cols) + len(other_h)))

    total_events = 0
    for cap in sorted(counts):
        oc     = counts[cap]
        row    = [oc.get(c, 0) for c in cols]
        other  = sum(v for k, v in oc.items() if k not in cols)
        total  = sum(oc.values())
        total_events += total
        vals   = "  ".join(f"{v:>8}" for v in row)
        print(f"{cap:<44}  {vals}  {other:>8}")

    print(f"\n{total_events} total event(s) across {len(counts)} capability ID(s).")
