"""Commerce records — Quote/Order/Payment, dispute bundle, scoped metrics (market wave; MKT-014/015/016/010/011).

The disciplines the requirements demand: a commerce record REFERENCES the governed records and never
embeds execution truth (MKT-015); payment is an EXTERNAL-rail reference, not a CHP primitive
(MKT-014); a dispute reconstructs from the records (MKT-016); and metrics are a per-capability
PROJECTION, never a stored universal score (MKT-010/011).
"""

import pytest

from chp_core import Order, Payment, Quote, dispute_bundle, scoped_metrics
from chp_core.commerce import INVOCATION_FIELDS


def _quote():
    return Quote(offer_ref="offer_1", requirement_ref="req_1", amount="19.99", currency="USD")


# ---- MKT-015: commerce records are DISTINCT from invocation records ----

def test_commerce_records_reference_never_embed_execution_truth():
    q = _quote()
    o = Order(quote_ref=q.id, resolution_ref="cres_1", buyer={"id": "buyer_a"})
    p = Payment(order_ref=o.id, rail="stripe", external_ref="pi_abc", amount="19.99", currency="USD")
    for rec in (q, o, p):
        keys = set(rec.to_dict())
        assert not (keys & INVOCATION_FIELDS), f"{type(rec).__name__} embeds execution truth: {keys & INVOCATION_FIELDS}"
    # they carry causal REFERENCES to the governed records
    assert o.to_dict()["resolution_ref"] == "cres_1" and o.to_dict()["quote_ref"] == q.id
    assert p.to_dict()["order_ref"] == o.id


def test_commerce_id_namespace_is_distinct():
    q = _quote()
    o = Order(quote_ref=q.id, resolution_ref="cres_1", buyer={"id": "b"})
    p = Payment(order_ref=o.id, rail="wire", external_ref="w1", amount="1", currency="USD")
    assert q.id.startswith("quo_") and o.id.startswith("ord_") and p.id.startswith("pay_")


# ---- MKT-014: payment is an external-rail reference, not a CHP primitive ----

def test_payment_links_an_external_rail():
    p = Payment(order_ref="ord_1", rail="stripe", external_ref="pi_xyz", amount="5.00", currency="EUR")
    d = p.to_dict()
    assert d["rail"] == "stripe" and d["external_ref"] == "pi_xyz"  # settlement lives on the rail
    assert "settled_at" not in d  # omit-when-absent until the rail settles


def test_order_and_payment_reject_bad_status():
    with pytest.raises(ValueError):
        Order(quote_ref="q", resolution_ref="r", buyer={"id": "b"}, status="paid")
    with pytest.raises(ValueError):
        Payment(order_ref="o", rail="x", external_ref="e", amount="1", currency="USD", status="done")


# ---- MKT-016: dispute bundle reconstructs from the records ----

def test_dispute_bundle_assembles_the_constituents():
    o = Order(quote_ref="quo_1", resolution_ref="cres_1", buyer={"id": "b"}, status="disputed")
    b = dispute_bundle(o, requirement_ref="req_1", resolution_ref="cres_1", offer_ref="offer_1",
                       evidence_refs=["evt_1", "evt_2"], reason="effect refuted")
    assert b["kind"] == "dispute-bundle" and b["order_ref"] == o.id
    assert b["requirement_ref"] == "req_1" and b["resolution_ref"] == "cres_1" and b["offer_ref"] == "offer_1"
    assert b["evidence_refs"] == ["evt_1", "evt_2"] and b["reason"] == "effect refuted"


# ---- MKT-010/011: scoped metrics are a per-capability projection, never a universal score ----

def test_scoped_metrics_projects_per_capability_and_never_folds_indeterminate():
    from chp_core import EffectEvidence

    def eff(det):
        return EffectEvidence(invocation_id="i", subject={"kind": "effect", "id": "e"},
                              determination=det, observer={"id": "o"})

    effects = [eff("confirmed"), eff("confirmed"), eff("indeterminate"), eff("refuted")]
    m = scoped_metrics(effects, capability="doc.summarize")
    assert m["capability"] == "doc.summarize" and m["observations"] == 4
    assert m["by_determination"]["indeterminate"] == 1  # surfaced, its own bucket
    assert m["confirmed_rate"] == 0.5  # 2/4 — indeterminate NOT folded into confirmed
    assert "score" not in m  # a projection, never a universal reputation number
    assert scoped_metrics([], capability="x")["confirmed_rate"] is None  # no observations → no rate
