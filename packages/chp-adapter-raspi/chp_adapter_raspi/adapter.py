"""RaspberryPiAdapter — physical-world capabilities for Raspberry Pi edge nodes.

Build order (validated against hardware availability):
  1. system_stats  — pure stdlib, works everywhere, proves cross-host evidence chain
  2. gpio_read     — requires gpiozero; injectable FakeGPIOBackend for CI
  3. gpio_write    — requires gpiozero; side_effects=["gpio_control"]
  4. camera_capture — requires picamera2; side_effects=["camera_access"]

Platform guard: non-Pi platforms (linux+aarch64/armv7l) get a RuntimeError describing
the mismatch. The adapter LOADS on all platforms so chp-host never crashes at import;
individual capability calls raise at invocation time.

Evidence policy:
  - system_stats values (CPU temp, memory, disk) are evidenced
  - GPIO pin + direction + value are evidenced
  - Camera: file_path, size_bytes, resolution evidenced; raw image bytes NEVER in evidence
"""

from __future__ import annotations

import platform
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from chp_core import BaseAdapter, capability

_EMITS = ["raspi_event", "raspi_error"]

_IS_LINUX = sys.platform == "linux"
_IS_PI = platform.machine() in ("armv7l", "aarch64")


def _require_pi() -> None:
    if not (_IS_LINUX and _IS_PI):
        raise RuntimeError(
            f"This capability requires a Raspberry Pi (linux+aarch64/armv7l). "
            f"Current platform: {sys.platform}/{platform.machine()}."
        )


# ---------------------------------------------------------------------------
# Injectable GPIO backend protocol (for tests)
# ---------------------------------------------------------------------------

class GPIOBackend(Protocol):
    def read(self, pin: int) -> bool: ...
    def write(self, pin: int, value: bool) -> None: ...


class FakeGPIOBackend:
    """In-memory GPIO for tests — no hardware required."""

    def __init__(self) -> None:
        self._pins: dict[int, bool] = {}

    def read(self, pin: int) -> bool:
        return self._pins.get(pin, False)

    def write(self, pin: int, value: bool) -> None:
        self._pins[pin] = value


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class RaspberryPiConfig:
    allowed_pins: list[int] | None = None
    image_save_dir: str = "/tmp/chp-camera"
    gpio_backend: GPIOBackend | None = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Live GPIO backend using gpiozero
# ---------------------------------------------------------------------------

class _GpiozeroBackend:
    def read(self, pin: int) -> bool:
        from gpiozero import Button  # type: ignore[import]
        b = Button(pin)
        val = b.is_pressed
        b.close()
        return val

    def write(self, pin: int, value: bool) -> None:
        from gpiozero import LED  # type: ignore[import]
        led = LED(pin)
        if value:
            led.on()
        else:
            led.off()
        led.close()


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class RaspberryPiAdapter(BaseAdapter):
    """Raspberry Pi physical-world access (GPIO, camera, system stats) as CHP capabilities."""

    adapter_id = "chp.adapters.raspi"
    adapter_name = "RaspberryPi"
    adapter_description = "Raspberry Pi GPIO control, camera capture, and system stats."
    adapter_category = "edge"
    adapter_tags = ["raspi", "gpio", "camera", "edge", "iot"]

    def __init__(self, config: RaspberryPiConfig | None = None) -> None:
        self._config = config or RaspberryPiConfig()

    def _gpio(self) -> GPIOBackend:
        if self._config.gpio_backend is not None:
            return self._config.gpio_backend
        _require_pi()
        return _GpiozeroBackend()

    def _check_pin(self, pin: int) -> None:
        allowed = self._config.allowed_pins
        if allowed is not None and pin not in allowed:
            raise ValueError(f"Pin {pin} is not in the allowed list: {allowed}")

    @capability(
        id="chp.adapters.raspi.system_stats",
        version="1.0.0",
        description="CPU temperature, memory, disk usage, and uptime. No hardware dependencies.",
        category="edge",
        provider="raspi",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def system_stats(self, ctx: Any, payload: Any) -> Any:
        ctx.emit("raspi_event", {"op": "system_stats"}, redacted=False)
        try:
            stats = _read_system_stats()
        except Exception as exc:
            ctx.emit("raspi_error", {"op": "system_stats", "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("raspi_event", {
            "op": "system_stats",
            "cpu_temp_c": stats.get("cpu_temp_c"),
            "memory_percent": stats.get("memory_percent"),
            "disk_percent": stats.get("disk_percent"),
        }, redacted=False)
        return stats

    @capability(
        id="chp.adapters.raspi.gpio_read",
        version="1.0.0",
        description="Read digital state of a GPIO pin.",
        category="edge",
        provider="raspi",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {"pin": {"type": "integer", "minimum": 0, "maximum": 40}},
            "required": ["pin"],
            "additionalProperties": False,
        },
    )
    async def gpio_read(self, ctx: Any, payload: Any) -> Any:
        pin: int = payload["pin"]
        self._check_pin(pin)
        gpio = self._gpio()
        ctx.emit("raspi_event", {"op": "gpio_read", "pin": pin, "direction": "in"}, redacted=False)
        try:
            value = gpio.read(pin)
        except Exception as exc:
            ctx.emit("raspi_error", {"op": "gpio_read", "pin": pin, "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("raspi_event", {
            "op": "gpio_read", "pin": pin, "direction": "in", "value": int(value),
        }, redacted=False)
        return {"pin": pin, "value": value, "value_int": int(value)}

    @capability(
        id="chp.adapters.raspi.gpio_write",
        version="1.0.0",
        description="Write digital state to a GPIO pin.",
        category="edge",
        provider="raspi",
        risk="high",
        side_effects=["gpio_control"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "pin": {"type": "integer", "minimum": 0, "maximum": 40},
                "value": {"type": "boolean"},
            },
            "required": ["pin", "value"],
            "additionalProperties": False,
        },
    )
    async def gpio_write(self, ctx: Any, payload: Any) -> Any:
        pin: int = payload["pin"]
        value: bool = bool(payload["value"])
        self._check_pin(pin)
        gpio = self._gpio()
        ctx.emit("raspi_event", {
            "op": "gpio_write", "pin": pin, "direction": "out", "value": int(value),
        }, redacted=False)
        try:
            gpio.write(pin, value)
        except Exception as exc:
            ctx.emit("raspi_error", {"op": "gpio_write", "pin": pin, "error": str(exc)[:500]}, redacted=False)
            raise
        ctx.emit("raspi_event", {
            "op": "gpio_write", "pin": pin, "direction": "out", "value": int(value), "status": "ok",
        }, redacted=False)
        return {"pin": pin, "value": value, "value_int": int(value), "status": "ok"}

    @capability(
        id="chp.adapters.raspi.camera_capture",
        version="1.0.0",
        description="Capture a still image. Returns file path, size, and resolution. Image bytes not in evidence.",
        category="edge",
        provider="raspi",
        risk="medium",
        side_effects=["camera_access"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "width": {"type": "integer", "minimum": 64, "maximum": 4056},
                "height": {"type": "integer", "minimum": 48, "maximum": 3040},
                "filename": {"type": "string"},
            },
            "additionalProperties": False,
        },
    )
    async def camera_capture(self, ctx: Any, payload: Any) -> Any:
        _require_pi()
        width: int = payload.get("width", 1920)
        height: int = payload.get("height", 1080)
        save_dir = Path(self._config.image_save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        filename = payload.get("filename") or f"chp_{int(time.time())}.jpg"
        dest = save_dir / filename

        ctx.emit("raspi_event", {
            "op": "camera_capture", "width": width, "height": height,
        }, redacted=False)
        try:
            from picamera2 import Picamera2  # type: ignore[import]
            cam = Picamera2()
            cam.configure(cam.create_still_configuration(main={"size": (width, height)}))
            cam.start()
            cam.capture_file(str(dest))
            cam.stop()
            cam.close()
        except Exception as exc:
            ctx.emit("raspi_error", {"op": "camera_capture", "error": str(exc)[:500]}, redacted=False)
            raise

        size_bytes = dest.stat().st_size
        ctx.emit("raspi_event", {
            "op": "camera_capture",
            "file_path": str(dest),
            "size_bytes": size_bytes,
            "resolution": f"{width}x{height}",
        }, redacted=False)
        return {
            "file_path": str(dest),
            "size_bytes": size_bytes,
            "resolution": f"{width}x{height}",
        }


# ---------------------------------------------------------------------------
# System stats — pure stdlib, works everywhere
# ---------------------------------------------------------------------------

def _read_system_stats() -> dict[str, Any]:
    stats: dict[str, Any] = {}

    # CPU temperature (Linux only)
    temp_path = Path("/sys/class/thermal/thermal_zone0/temp")
    if temp_path.exists():
        try:
            stats["cpu_temp_c"] = round(int(temp_path.read_text().strip()) / 1000, 1)
        except Exception:
            stats["cpu_temp_c"] = None
    else:
        stats["cpu_temp_c"] = None

    # Memory via /proc/meminfo
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            mem: dict[str, int] = {}
            for line in meminfo_path.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(":")] = int(parts[1])
            total = mem.get("MemTotal", 0)
            available = mem.get("MemAvailable", 0)
            used = total - available
            stats["memory_total_mb"] = round(total / 1024)
            stats["memory_used_mb"] = round(used / 1024)
            stats["memory_percent"] = round(used / total * 100, 1) if total else None
        except Exception:
            stats["memory_total_mb"] = None
            stats["memory_used_mb"] = None
            stats["memory_percent"] = None
    else:
        stats["memory_total_mb"] = None
        stats["memory_used_mb"] = None
        stats["memory_percent"] = None

    # Disk (root filesystem)
    disk = shutil.disk_usage("/")
    stats["disk_total_gb"] = round(disk.total / 1024**3, 2)
    stats["disk_used_gb"] = round(disk.used / 1024**3, 2)
    stats["disk_percent"] = round(disk.used / disk.total * 100, 1)

    # Uptime via /proc/uptime
    uptime_path = Path("/proc/uptime")
    if uptime_path.exists():
        try:
            stats["uptime_seconds"] = int(float(uptime_path.read_text().split()[0]))
        except Exception:
            stats["uptime_seconds"] = None
    else:
        stats["uptime_seconds"] = None

    stats["platform"] = f"{sys.platform}/{platform.machine()}"
    return stats
