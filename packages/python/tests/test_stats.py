"""Tests for chp_core.stats.collect_host_stats().

Assertions are platform-tolerant — the suite runs on macOS (CI and dev) and
Linux (CI). Never raises; all optional fields are None rather than absent when
the platform doesn't support them.
"""

from __future__ import annotations

import sys

import pytest

from chp_core.stats import collect_host_stats


# ---------------------------------------------------------------------------
# Smoke / never-raises
# ---------------------------------------------------------------------------

def test_collect_host_stats_never_raises():
    """collect_host_stats() must not raise on any platform."""
    stats = collect_host_stats()
    assert isinstance(stats, dict)


# ---------------------------------------------------------------------------
# Mandatory keys always present
# ---------------------------------------------------------------------------

EXPECTED_KEYS = [
    "platform",
    "cpu_count",
    "load_avg",
    "load_per_core",
    "memory",
    "disk",
    "uptime_seconds",
    "cpu_temp_c",
    "gpu",
]


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_expected_key_present(key):
    stats = collect_host_stats()
    assert key in stats, f"Missing key: {key!r}"


# ---------------------------------------------------------------------------
# cpu_count
# ---------------------------------------------------------------------------

def test_cpu_count_is_positive_int():
    stats = collect_host_stats()
    assert isinstance(stats["cpu_count"], int)
    assert stats["cpu_count"] >= 1


# ---------------------------------------------------------------------------
# platform string
# ---------------------------------------------------------------------------

def test_platform_string_format():
    stats = collect_host_stats()
    plat = stats["platform"]
    assert isinstance(plat, str)
    assert "/" in plat, f"Expected 'os/arch' format, got: {plat!r}"


# ---------------------------------------------------------------------------
# load_avg — present on macOS and Linux
# ---------------------------------------------------------------------------

def test_load_avg_present_on_supported_platform():
    stats = collect_host_stats()
    if sys.platform in ("darwin", "linux"):
        assert stats["load_avg"] is not None, "load_avg should be present on macOS/Linux"
        assert isinstance(stats["load_avg"], list)
        assert len(stats["load_avg"]) == 3
        for val in stats["load_avg"]:
            assert isinstance(val, float)
            assert val >= 0.0


def test_load_per_core_present_when_load_avg_available():
    stats = collect_host_stats()
    if stats["load_avg"] is not None and stats["cpu_count"]:
        assert stats["load_per_core"] is not None
        assert isinstance(stats["load_per_core"], float)
        assert stats["load_per_core"] >= 0.0


# ---------------------------------------------------------------------------
# disk — always present
# ---------------------------------------------------------------------------

def test_disk_present_and_has_expected_keys():
    stats = collect_host_stats()
    disk = stats["disk"]
    assert disk is not None, "disk should always be present"
    assert "total_gb" in disk
    assert "used_gb" in disk
    assert "percent" in disk


def test_disk_values_valid():
    stats = collect_host_stats()
    disk = stats["disk"]
    assert disk["total_gb"] > 0
    assert disk["used_gb"] >= 0
    assert 0.0 <= disk["percent"] <= 100.0


# ---------------------------------------------------------------------------
# memory — present on macOS and Linux
# ---------------------------------------------------------------------------

def test_memory_present_on_supported_platform():
    stats = collect_host_stats()
    if sys.platform in ("darwin", "linux"):
        assert stats["memory"] is not None, "memory should be present on macOS/Linux"
        mem = stats["memory"]
        assert "total_mb" in mem
        assert "used_mb" in mem
        assert "percent" in mem


def test_memory_total_mb_positive_when_present():
    stats = collect_host_stats()
    mem = stats["memory"]
    if mem is not None and mem.get("total_mb") is not None:
        assert mem["total_mb"] > 0


# ---------------------------------------------------------------------------
# gpu — key must exist; may be dict or None
# ---------------------------------------------------------------------------

def test_gpu_key_exists():
    stats = collect_host_stats()
    assert "gpu" in stats


def test_gpu_is_dict_or_none():
    stats = collect_host_stats()
    gpu = stats["gpu"]
    assert gpu is None or isinstance(gpu, dict)


def test_gpu_dict_has_utilization_pct_when_present():
    stats = collect_host_stats()
    gpu = stats["gpu"]
    if gpu is not None:
        assert "utilization_pct" in gpu
        assert isinstance(gpu["utilization_pct"], int)
        assert "source" in gpu


# ---------------------------------------------------------------------------
# uptime / cpu_temp — Linux only; None on macOS
# ---------------------------------------------------------------------------

def test_uptime_seconds_is_int_or_none():
    stats = collect_host_stats()
    val = stats["uptime_seconds"]
    if val is not None:
        assert isinstance(val, int)
        assert val > 0


def test_cpu_temp_is_float_or_none():
    stats = collect_host_stats()
    val = stats["cpu_temp_c"]
    if val is not None:
        assert isinstance(val, (int, float))
        # Sanity: temperature in celsius for a real CPU
        assert 0 < val < 200


def test_uptime_and_temp_none_on_macos():
    """On macOS these should be None (no /proc)."""
    if sys.platform == "darwin":
        stats = collect_host_stats()
        assert stats["uptime_seconds"] is None
        assert stats["cpu_temp_c"] is None
