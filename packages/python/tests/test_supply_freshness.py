"""Offer validity enforcement: expired/not-yet-valid supply never resolves as
current (the DISC-005 / INTRO-034 rule, enforced at the supply->resolve seam).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from chp_core.resolver import offer_to_candidate
from chp_core.supply import CapabilityOffer, current_offers, offer_validity_state


def _offer(validity=None):
    return CapabilityOffer(binding={"id": "b1"}, provider={"id": "p"},
                           evidence_contract={"id": "ec"}, validity=validity or {})


def test_validity_states():
    at = "2026-08-25T12:00:00Z"
    assert offer_validity_state(_offer(), at) == "unbounded"
    assert offer_validity_state(_offer({"valid_until": "2026-08-25T11:00:00Z"}), at) == "expired"
    assert offer_validity_state(_offer({"valid_from": "2026-08-25T13:00:00Z"}), at) == "not_yet_valid"
    assert offer_validity_state(
        _offer({"valid_from": "2026-08-25T11:00:00Z", "valid_until": "2026-08-25T13:00:00Z"}),
        at) == "current"
    # Boundary: valid_until is exclusive — at the expiry instant the offer is expired.
    assert offer_validity_state(_offer({"valid_until": at}), at) == "expired"
    # Dict-shaped offers work identically.
    assert offer_validity_state({"validity": {"valid_until": "2020-01-01T00:00:00Z"}}, at) == "expired"


def test_expired_offer_refused_at_the_resolve_seam():
    with pytest.raises(ValueError, match="expired"):
        offer_to_candidate(_offer({"valid_until": "2020-01-01T00:00:00Z"}), satisfied_hard=[])
    with pytest.raises(ValueError, match="not_yet_valid"):
        offer_to_candidate(_offer({"valid_from": "2099-01-01T00:00:00Z"}), satisfied_hard=[])


def test_current_and_unbounded_offers_still_resolve():
    cand = offer_to_candidate(_offer(), satisfied_hard=["h1"])
    assert cand.binding == {"id": "b1"} and cand.offer["id"].startswith("offer")
    live = _offer({"valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"})
    assert offer_to_candidate(live, satisfied_hard=[]).offer["version"] == "1"


def test_current_offers_filter():
    good, stale = _offer(), _offer({"valid_until": "2020-01-01T00:00:00Z"})
    assert current_offers([good, stale]) == [good]
