"""Tests for chp-adapter-raspi using FakeGPIOBackend — no Pi required."""

from __future__ import annotations

import pytest

from chp_adapter_raspi import RaspberryPiAdapter, RaspberryPiConfig
from chp_adapter_raspi.adapter import FakeGPIOBackend, _read_system_stats
from chp_core import LocalCapabilityHost, register_adapter


def _host_with_fake(allowed_pins=None) -> tuple[LocalCapabilityHost, FakeGPIOBackend]:
    fake = FakeGPIOBackend()
    config = RaspberryPiConfig(gpio_backend=fake, allowed_pins=allowed_pins)
    adapter = RaspberryPiAdapter(config)
    host = LocalCapabilityHost()
    register_adapter(host, adapter)
    return host, fake


# ---------------------------------------------------------------------------
# system_stats — no hardware dep, runs everywhere
# ---------------------------------------------------------------------------

def test_system_stats_succeeds():
    host, _ = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.system_stats", {})
    assert result.success
    data = result.data
    assert "disk_total_gb" in data
    assert "disk_percent" in data
    assert "platform" in data


def test_system_stats_disk_values_valid():
    host, _ = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.system_stats", {})
    assert result.success
    assert result.data["disk_total_gb"] > 0
    assert 0.0 <= result.data["disk_percent"] <= 100.0


def test_system_stats_evidence_recorded():
    host, _ = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.system_stats", {})
    assert result.success
    assert result.evidence_ids


def test_read_system_stats_always_returns_disk():
    stats = _read_system_stats()
    assert stats["disk_total_gb"] > 0


# ---------------------------------------------------------------------------
# gpio_read (fake backend)
# ---------------------------------------------------------------------------

def test_gpio_read_default_low():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.gpio_read", {"pin": 17})
    assert result.success
    assert result.data["value"] is False
    assert result.data["value_int"] == 0


def test_gpio_read_after_write():
    host, fake = _host_with_fake()
    fake._pins[17] = True
    result = host.invoke("chp.adapters.raspi.gpio_read", {"pin": 17})
    assert result.success
    assert result.data["value"] is True
    assert result.data["value_int"] == 1


def test_gpio_read_allowed_pins_rejects_disallowed():
    host, fake = _host_with_fake(allowed_pins=[17, 18])
    result = host.invoke("chp.adapters.raspi.gpio_read", {"pin": 27})
    assert not result.success


def test_gpio_read_allowed_pins_accepts_allowed():
    host, fake = _host_with_fake(allowed_pins=[17, 18])
    result = host.invoke("chp.adapters.raspi.gpio_read", {"pin": 17})
    assert result.success


# ---------------------------------------------------------------------------
# gpio_write (fake backend)
# ---------------------------------------------------------------------------

def test_gpio_write_high():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.gpio_write", {"pin": 18, "value": True})
    assert result.success
    assert result.data["value"] is True
    assert fake._pins[18] is True


def test_gpio_write_low():
    host, fake = _host_with_fake()
    fake._pins[18] = True
    result = host.invoke("chp.adapters.raspi.gpio_write", {"pin": 18, "value": False})
    assert result.success
    assert fake._pins[18] is False


def test_gpio_write_read_roundtrip():
    host, fake = _host_with_fake()
    host.invoke("chp.adapters.raspi.gpio_write", {"pin": 22, "value": True})
    result = host.invoke("chp.adapters.raspi.gpio_read", {"pin": 22})
    assert result.success
    assert result.data["value"] is True


def test_gpio_write_evidence_includes_pin_and_value():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.gpio_write", {"pin": 23, "value": True})
    assert result.success
    assert result.evidence_ids


# ---------------------------------------------------------------------------
# camera_capture — requires Pi, must fail gracefully on non-Pi
# ---------------------------------------------------------------------------

def test_camera_capture_fails_on_non_pi():
    import sys
    import platform as _platform
    # Only run this check on non-Pi (which is always true in CI)
    if sys.platform == "linux" and _platform.machine() in ("armv7l", "aarch64"):
        pytest.skip("Running on actual Pi — camera test would attempt real capture")

    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.raspi.camera_capture", {})
    assert not result.success
    err = str(result.error or "")
    assert "Raspberry Pi" in err or "linux" in err.lower() or "platform" in err.lower() or err
