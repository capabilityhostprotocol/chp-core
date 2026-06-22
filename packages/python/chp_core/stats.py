"""Cross-platform host statistics collector — pure stdlib + short guarded subprocesses.

No third-party dependencies (no psutil). Safe to import on any OS without side effects.
All values are best-effort; returns None for any field that is unavailable or fails.

Usage::

    from chp_core.stats import collect_host_stats
    stats = collect_host_stats()
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from typing import Any


def _bin(name: str) -> str:
    """Absolute path to a system tool, independent of $PATH.

    Services (launchd/systemd) run with a minimal PATH that often omits
    /usr/sbin, so bare names like ``ioreg``/``sysctl`` fail there. Resolve to an
    absolute path from the standard locations; fall back to the bare name.
    """
    for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return name


def _memory_linux() -> dict[str, Any] | None:
    """Parse /proc/meminfo and return {total_mb, used_mb, percent}."""
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(":")] = int(parts[1])
        total_kb = mem.get("MemTotal", 0)
        available_kb = mem.get("MemAvailable", 0)
        if not total_kb:
            return None
        used_kb = total_kb - available_kb
        return {
            "total_mb": round(total_kb / 1024),
            "used_mb": round(used_kb / 1024),
            "percent": round(used_kb / total_kb * 100, 1),
        }
    except Exception:
        return None


def _memory_macos() -> dict[str, Any] | None:
    """Get macOS memory info from sysctl + vm_stat."""
    try:
        # Total physical memory
        result = subprocess.run(
            [_bin("sysctl"), "-n", "hw.memsize"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            return None
        total_bytes = int(result.stdout.strip())
        total_mb = round(total_bytes / (1024 * 1024))
    except Exception:
        return None

    try:
        # vm_stat output: parse page size and active/wired/compressor counts
        result = subprocess.run(
            [_bin("vm_stat")],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            return None
        lines = result.stdout.splitlines()
        # First line: "Mach Virtual Memory Statistics: (page size of NNNN bytes)"
        page_size = 4096  # default
        m = re.search(r"page size of (\d+) bytes", lines[0] if lines else "")
        if m:
            page_size = int(m.group(1))

        pages: dict[str, int] = {}
        for line in lines[1:]:
            # e.g. "Pages active:                        123456."
            m2 = re.match(r"^Pages\s+(\w+):\s+(\d+)", line)
            if m2:
                pages[m2.group(1).lower()] = int(m2.group(2))

        # active + wired + occupied by compressor ≈ used
        used_pages = (
            pages.get("active", 0)
            + pages.get("wired", 0)  # "wired down" appears as "wired"
            + pages.get("occupied", 0)  # "occupied by compressor"
        )
        used_mb = round(used_pages * page_size / (1024 * 1024))
        percent = round(used_mb / total_mb * 100, 1) if total_mb else None
        return {
            "total_mb": total_mb,
            "used_mb": used_mb,
            "percent": percent,
        }
    except Exception:
        # Fall back: total only
        return {
            "total_mb": total_mb,
            "used_mb": None,
            "percent": None,
        }


def _gpu_apple_silicon() -> dict[str, Any] | None:
    """Query Apple Silicon GPU utilization via ioreg."""
    try:
        result = subprocess.run(
            [_bin("ioreg"), "-r", "-c", "IOAccelerator", "-d", "1"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0 or not result.stdout:
            return None
        text = result.stdout

        # Extract utilization percentage
        util_match = re.search(r'"Device Utilization %"\s*=\s*(\d+)', text)
        if not util_match:
            return None
        utilization_pct = int(util_match.group(1))

        # Try to find accelerator name
        name_match = re.search(r'"IOClass"\s*=\s*"([^"]+)"', text)
        name = name_match.group(1) if name_match else None

        return {
            "utilization_pct": utilization_pct,
            "name": name,
            "source": "ioreg",
        }
    except Exception:
        return None


def _gpu_nvidia() -> dict[str, Any] | None:
    """Query NVIDIA GPU via nvidia-smi."""
    if shutil.which("nvidia-smi") is None:
        return None
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        parts = [p.strip() for p in result.stdout.strip().split(",")]
        if len(parts) < 3:
            return None
        return {
            "utilization_pct": int(parts[0]),
            "memory_used_mb": int(parts[1]),
            "memory_total_mb": int(parts[2]),
            "source": "nvidia-smi",
        }
    except Exception:
        return None


def collect_host_stats() -> dict[str, Any]:
    """Collect host statistics using only stdlib + short guarded subprocesses.

    Returns a dict with the following keys (None when unavailable on the platform):
      - platform:        str  e.g. "darwin/arm64"
      - cpu_count:       int  logical CPU count
      - load_avg:        list[float] | None  1/5/15-min load averages
      - load_per_core:   float | None  load_avg[0] / cpu_count (rounded to 3dp)
      - memory:          dict | None  {total_mb, used_mb, percent}
      - disk:            dict  {total_gb, used_gb, percent}  (always present)
      - uptime_seconds:  int | None  (Linux only)
      - cpu_temp_c:      float | None  (Linux only)
      - gpu:             dict | None  best-effort GPU info

    Never raises; errors are silently converted to None for the relevant field.
    """
    stats: dict[str, Any] = {}

    # Platform
    stats["platform"] = f"{sys.platform}/{platform.machine()}"

    # CPU count
    stats["cpu_count"] = os.cpu_count()

    # Load average
    load_avg: list[float] | None = None
    try:
        raw = os.getloadavg()
        load_avg = [round(x, 3) for x in raw]
    except (AttributeError, OSError):
        load_avg = None
    stats["load_avg"] = load_avg

    # Load per core (normalised headroom)
    if load_avg is not None and stats["cpu_count"]:
        stats["load_per_core"] = round(load_avg[0] / stats["cpu_count"], 3)
    else:
        stats["load_per_core"] = None

    # Memory
    if sys.platform == "linux":
        stats["memory"] = _memory_linux()
    elif sys.platform == "darwin":
        stats["memory"] = _memory_macos()
    else:
        stats["memory"] = None

    # Disk (always present)
    try:
        disk = shutil.disk_usage("/")
        stats["disk"] = {
            "total_gb": round(disk.total / 1024 ** 3, 2),
            "used_gb": round(disk.used / 1024 ** 3, 2),
            "percent": round(disk.used / disk.total * 100, 1),
        }
    except Exception:
        stats["disk"] = None

    # Uptime (Linux only)
    if sys.platform == "linux":
        try:
            with open("/proc/uptime") as fh:
                stats["uptime_seconds"] = int(float(fh.read().split()[0]))
        except Exception:
            stats["uptime_seconds"] = None
    else:
        stats["uptime_seconds"] = None

    # CPU temperature (Linux only)
    if sys.platform == "linux":
        try:
            temp_path = "/sys/class/thermal/thermal_zone0/temp"
            with open(temp_path) as fh:
                stats["cpu_temp_c"] = round(int(fh.read().strip()) / 1000, 1)
        except Exception:
            stats["cpu_temp_c"] = None
    else:
        stats["cpu_temp_c"] = None

    # GPU — best-effort
    if sys.platform == "darwin":
        stats["gpu"] = _gpu_apple_silicon()
    elif sys.platform == "linux":
        stats["gpu"] = _gpu_nvidia()
    else:
        stats["gpu"] = None

    return stats
