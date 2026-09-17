"""huggingface.quantize — AWQ/GPTQ pass-through + calibration-text redaction.

The real backend imports autoawq/gptqmodel (GPU-only), so a fake backend stands in for the lib call.
Proves the cap threads method/bits/group_size/calibration to the backend, returns the quantized-dir
result, and never leaks calibration text or weights into the return (evidence emits count-only).
"""
from __future__ import annotations

import asyncio
import json

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_huggingface import HuggingFaceAdapter, HuggingFaceConfig

_SECRET_CALIB = "PROPRIETARY-DOMAIN-CALIBRATION-SAMPLE-42"


class _FakeQuantBackend:
    """Records the quantize call; returns a dir result like autoawq/gptqmodel would."""
    def __init__(self):
        self.call = None

    def quantize(self, model_path, output_path, method, bits, group_size, calibration):
        self.call = dict(model_path=model_path, output_path=output_path, method=method,
                         bits=bits, group_size=group_size, calibration=calibration)
        return {"output_path": output_path, "method": method, "bits": bits,
                "group_size": group_size, "output_size_bytes": 123_456}


def _host(backend):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HuggingFaceAdapter(HuggingFaceConfig(_backend=backend)))
    return host


def test_quantize_passthrough_and_redacts_calibration():
    be = _FakeQuantBackend()
    res = asyncio.get_event_loop().run_until_complete(_host(be).ainvoke(
        "chp.adapters.huggingface.quantize",
        {"model_path": "/models/m", "output_path": "/models/m-awq", "method": "gptq",
         "bits": 4, "group_size": 64, "calibration": [_SECRET_CALIB, "another sample"]},
    ))
    assert res.success, res
    # pass-through: every knob reached the backend
    assert be.call["method"] == "gptq" and be.call["bits"] == 4 and be.call["group_size"] == 64
    assert be.call["calibration"] == [_SECRET_CALIB, "another sample"]
    # return shape (the vLLM-loadable dir)
    assert res.data["output_path"] == "/models/m-awq" and res.data["output_size_bytes"] == 123_456
    # redaction: calibration text never rides the return
    assert _SECRET_CALIB not in json.dumps(res.data)


def test_default_method_is_gptq_and_default_calibration():
    be = _FakeQuantBackend()
    res = asyncio.get_event_loop().run_until_complete(_host(be).ainvoke(
        "chp.adapters.huggingface.quantize",
        {"model_path": "/models/m", "output_path": "/models/m-q"},  # method defaults to gptq (autoawq is dead)
    ))
    assert res.success, res
    assert be.call["method"] == "gptq" and be.call["bits"] == 4 and be.call["group_size"] == 128
    assert be.call["calibration"] is None   # backend applies its own _DEFAULT_CALIB


# --- container execution mode -------------------------------------------------

from chp_core import BaseAdapter, capability  # noqa: E402


_RESULT_JSON = ('{"output_path": "/work/out", "method": "gptq", "bits": 4, '
                '"group_size": 128, "output_size_bytes": 999, "secs": 12.3}')


class _FakeContainer(BaseAdapter):
    """Stand-in for chp.adapters.container.run — records the run; stdout has NO marker (as when the
    quantizer's progress spam truncates it), so the result must come from the file the entrypoint wrote."""
    adapter_id = "chp.adapters.container"

    def __init__(self):
        self.run_payload = None

    @capability(id="chp.adapters.container.run", version="1.0.0",
                description="test container run", category="runtime", risk="high")
    async def run(self, ctx, payload):  # noqa: ANN001
        self.run_payload = payload
        return {"exit_code": 0, "stdout": "Quantizing fc1 in layer [1 of 11] ... (marker truncated)"}


class _FakeFs(BaseAdapter):
    adapter_id = "chp.adapters.filesystem"

    def __init__(self):
        self.written = None

    @capability(id="chp.adapters.filesystem.write_file", version="1.0.0",
                description="test write", category="data", risk="low")
    async def write_file(self, ctx, payload):  # noqa: ANN001
        self.written = payload
        return {"created": True, "path": payload["path"]}

    @capability(id="chp.adapters.filesystem.read_file", version="1.0.0",
                description="test read", category="data", risk="low")
    async def read_file(self, ctx, payload):  # noqa: ANN001
        assert payload["path"].endswith(".chp_result.json")
        return {"content": _RESULT_JSON}


def test_quantize_container_mode_composes_container_run_and_redacts_calib():
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HuggingFaceAdapter(HuggingFaceConfig(_backend=_FakeQuantBackend())))
    container = _FakeContainer(); fs = _FakeFs()
    register_adapter(host, container)
    register_adapter(host, fs)

    res = asyncio.get_event_loop().run_until_complete(host.ainvoke(
        "chp.adapters.huggingface.quantize",
        {"model_path": "facebook/opt-125m", "output_path": "/host/out", "execution": "container",
         "method": "gptq", "bits": 4, "calibration": [_SECRET_CALIB]}))
    assert res.success, res
    p = container.run_payload
    # composed container.run: GPU image + entrypoint args, output dir mounted, repo id NOT mounted (pulled)
    assert p["image"] == "chp-quant:gptq" and p["gpus"] == "all" and p["detach"] is False
    assert p["timeout"] >= 1800   # quantize must not be cut short by the container's default timeout
    assert p["volumes"] == ["/host/out:/work/out"]
    assert p["command"][:4] == ["--model", "facebook/opt-125m", "--out", "/work/out"]
    assert "--method" in p["command"] and "gptq" in p["command"]
    # calibration went to the filesystem cap (mounted file), NEVER into argv or evidence
    assert _SECRET_CALIB in (fs.written or {}).get("content", "")
    assert all(_SECRET_CALIB not in str(a) for a in p["command"])
    assert "--calib-file" in p["command"]
    # the container's CHP_QUANTIZE_RESULT was parsed into the cap result
    assert res.data["output_size_bytes"] == 999 and res.data["method"] == "gptq"
    assert _SECRET_CALIB not in json.dumps(res.data)


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
