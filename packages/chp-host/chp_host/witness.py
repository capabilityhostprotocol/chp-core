"""The mesh witnessing loop (chp-v0.2.md §12, proposal 0005).

Each tick, this node fetches every peer's store head (`GET /head`), signs a
chain-witness statement over it with its OWN key, keeps the issued statement
locally (the record the witnessed operator cannot delete), delivers it back
(`POST /witness` — the peer verifies and keeps the receipt + leaves snapshot),
and stamps ``last_witness`` on the mesh manifest entry.

Opt-in via ``gateway.witness_interval_s`` (default off), the prober pattern.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.request

from chp_core.types import JSON, utc_now


def witness_peer(url: str, api_key: str | None, witness_key, witness_id: str,
                 timeout: int = 15) -> JSON | None:
    """One witness exchange with one peer. Returns the issued statement, or
    None when the peer has no /head (old host) or is unreachable."""
    from chp_core.signing import build_chain_witness
    from chp_core.witnessing import record_issued

    from .mesh import mark_witnessed

    def _request(path: str, body: JSON | None = None) -> JSON:
        req = urllib.request.Request(
            f"{url.rstrip('/')}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"X-CHP-Key": api_key} if api_key else {})},
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    try:
        head = _request("/head")
    except Exception:
        return None  # unreachable or pre-§12 peer — witnessing is best-effort
    statement = build_chain_witness(
        str(head["host_id"]), int(head["sequence"]), str(head["store_head"]),
        witness_key, witness_id=witness_id, witnessed_at=utc_now())
    # The issued record is the threat-model core: keep it BEFORE delivery —
    # even if the peer refuses the receipt, our countersignature exists.
    record_issued(statement)
    mark_witnessed(url, int(head["sequence"]), str(head["store_head"]))
    try:
        _request("/witness", statement)
    except Exception as exc:  # noqa: BLE001 — delivery is best-effort
        print(f"  WARNING: witness delivery to {url} failed: {exc}", file=sys.stderr)
    return statement


def start_witness_loop(remotes: list, witness_id: str, interval_s: float):
    """Daemon loop witnessing every remote each tick (§12; opt-in). *remotes*
    is [(url, api_key)]. Returns a zero-arg stop callable, or None when this
    host has no signing key (a witness must be able to sign)."""
    from chp_core.signing import load_host_key, resolve_key_dir

    key = load_host_key(resolve_key_dir(witness_id))
    if key is None or not key.can_sign:
        print(f"  WARNING: witnessing disabled — no signing key for {witness_id!r} "
              "(run `chp keygen`)", file=sys.stderr)
        return None

    stop = threading.Event()

    def _loop() -> None:
        while not stop.wait(interval_s):
            for url, api_key in remotes:
                try:
                    witness_peer(url, api_key, key, witness_id)
                except Exception:  # noqa: BLE001 — one peer must not kill the loop
                    pass

    threading.Thread(target=_loop, daemon=True,
                     name=f"chp-witness-{witness_id}").start()
    return stop.set
