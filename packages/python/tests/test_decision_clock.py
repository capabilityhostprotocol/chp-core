"""AGY-008: time-dependent decisions use an explicit, injectable decision clock (RFC 3339)."""
from chp_core import LocalCapabilityHost


def test_injected_decision_clock_is_used():
    host = LocalCapabilityHost(clock=lambda: "2020-01-01T00:00:00Z")
    assert host._decision_now() == "2020-01-01T00:00:00Z"


def test_default_decision_clock_is_wall_clock():
    host = LocalCapabilityHost()
    now = host._decision_now()
    assert isinstance(now, str) and now.endswith("Z")  # RFC 3339 wall clock
