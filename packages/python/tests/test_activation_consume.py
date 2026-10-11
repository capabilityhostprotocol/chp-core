"""Host-side atomic single-use consume store for activation grants (M1.3 wiring)."""
from __future__ import annotations

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor

from chp_core.activation_consume import ActivationConsumeStore


def test_first_consume_wins_second_is_replay():
    s = ActivationConsumeStore()
    assert s.consume("ap1") is True       # first winner
    assert s.consume("ap1") is False      # replay rejected
    assert s.is_consumed("ap1") is True
    assert s.consumed_ids() == {"ap1"}


def test_empty_or_nonstring_id_never_consumes():
    s = ActivationConsumeStore()
    assert s.consume("") is False
    assert s.consume(None) is False       # type: ignore[arg-type]
    assert s.consumed_ids() == set()


def test_distinct_ids_independent():
    s = ActivationConsumeStore()
    assert s.consume("a") is True and s.consume("b") is True
    assert s.consumed_ids() == {"a", "b"}


def test_durable_across_reopen(tmp_path):
    path = str(tmp_path / "consume.db")
    s1 = ActivationConsumeStore(path); assert s1.consume("ap1") is True; s1.close()
    s2 = ActivationConsumeStore(path)  # reopen the same file
    assert s2.consume("ap1") is False  # still consumed after restart


def test_concurrent_consume_exactly_one_winner(tmp_path):
    # the real double-spend guard: N racing consumes of the SAME id → exactly ONE True.
    path = str(tmp_path / "race.db")
    stores = [ActivationConsumeStore(path) for _ in range(16)]
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda st: st.consume("hot"), stores))
    assert sum(1 for r in results if r) == 1, f"exactly one winner, got {sum(results)}"
    for st in stores:
        st.close()


def test_concurrent_consume_shared_instance_one_winner():
    # ONE store shared across threads (the host's single :memory: instance) must still yield exactly
    # one winner — the shared sqlite connection is serialized by the instance lock (review F-1/F-2).
    s = ActivationConsumeStore()  # :memory:, single instance
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda _i: s.consume("hot"), range(16)))
    assert sum(1 for r in results if r) == 1, f"exactly one winner, got {sum(results)}"
