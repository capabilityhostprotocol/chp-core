"""Tests for chp-adapter-mlx.

A fake ``chp.adapters.http`` capability is registered on the host, so these tests
exercise the real lego-block composition path (MLXAdapter → ctx.ainvoke →
http.request) with no mlx_lm server and no HTTP library.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from chp_adapter_mlx import MLXAdapter, MLXConfig
from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# Fake http adapter — canned mlx_lm OpenAI responses (optionally "server down")
# ---------------------------------------------------------------------------

class FakeHttpAdapter(BaseAdapter):
    adapter_id = "chp.adapters.http"
    adapter_name = "FakeHttp"
    adapter_description = "Canned mlx_lm OpenAI responses for composition tests."
    adapter_category = "execution"

    def __init__(self, server_up: bool = True) -> None:
        self._server_up = server_up

    @capability(
        id="chp.adapters.http.request",
        version="1.0.0",
        description="Fake HTTP request returning canned mlx_lm payloads by URL path.",
        category="execution",
        risk="low",
        emits=["http_request", "http_response"],
        input_schema={
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "json_body": {},
                "timeout": {"type": "number"},
            },
            "required": ["method", "url"],
            "additionalProperties": False,
        },
    )
    async def request(self, ctx: Any, payload: dict) -> dict:
        url = payload["url"]
        ctx.emit("http_request", {"method": payload["method"], "url": url}, redacted=False)

        if not self._server_up:
            return {"status_code": 503, "json": None, "body": "", "headers": {}}

        if url.endswith("/v1/completions"):
            body = {
                "choices": [{"text": "GENERATED_COMPLETION_TEXT", "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 11, "total_tokens": 18},
            }
        elif url.endswith("/v1/chat/completions"):
            body = {
                "choices": [{"message": {"role": "assistant", "content": "CHAT_REPLY_TEXT"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 5, "total_tokens": 14},
            }
        elif url.endswith("/v1/models"):
            body = {"data": [{"id": "mlx-community/Qwen3-4B-4bit", "owned_by": "mlx"}]}
        else:
            return {"status_code": 404, "json": None, "body": "", "headers": {}}

        ctx.emit("http_response", {"url": url, "status_code": 200}, redacted=False)
        return {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": "",
            "json": body,
            "content_type": "application/json",
            "url": url,
            "duration_ms": 1,
        }


def _make_host(default_model: str = "test-model", server_up: bool = True) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, FakeHttpAdapter(server_up=server_up))
    register_adapter(host, MLXAdapter(MLXConfig(default_model=default_model)))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


# ---------------------------------------------------------------------------
# MLXConfig
# ---------------------------------------------------------------------------

class TestMLXConfig:
    def test_default_base_url(self, monkeypatch):
        monkeypatch.delenv("MLX_BASE_URL", raising=False)
        assert MLXConfig().resolved_base_url() == "http://localhost:8081"

    def test_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("MLX_BASE_URL", "http://mlx:9000")
        assert MLXConfig().resolved_base_url() == "http://mlx:9000"

    def test_model_from_env(self, monkeypatch):
        monkeypatch.setenv("MLX_MODEL", "mlx-community/model")
        assert MLXConfig().resolved_default_model() == "mlx-community/model"


# ---------------------------------------------------------------------------
# generate / chat / list_models
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_returns_text_and_tokens(self):
        result = _invoke(_make_host(), "chp.adapters.mlx.generate", {"prompt": "Hello"})
        assert result.success
        assert result.data["text"] == "GENERATED_COMPLETION_TEXT"
        assert result.data["prompt_tokens"] == 7
        assert result.data["completion_tokens"] == 11
        assert result.data["finish_reason"] == "stop"

    def test_prompt_and_completion_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.mlx.generate", {"prompt": "SECRET_PROMPT_XYZ"})
        assert result.success
        for evt in host.replay(result.invocation_id):
            blob = str(evt.get("payload", {}))
            assert "SECRET_PROMPT_XYZ" not in blob
            assert "GENERATED_COMPLETION_TEXT" not in blob

    def test_missing_model_raises(self):
        result = _invoke(_make_host(default_model=""), "chp.adapters.mlx.generate", {"prompt": "Hello"})
        assert not result.success


class TestChat:
    def test_returns_message_and_tokens(self):
        result = _invoke(_make_host(), "chp.adapters.mlx.chat", {
            "messages": [{"role": "user", "content": "hi"}],
        })
        assert result.success
        assert result.data["message"]["content"] == "CHAT_REPLY_TEXT"
        assert result.data["prompt_tokens"] == 9

    def test_message_content_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.mlx.chat", {
            "messages": [{"role": "user", "content": "SECRET_MESSAGE_ABC"}],
        })
        assert result.success
        for evt in host.replay(result.invocation_id):
            assert "SECRET_MESSAGE_ABC" not in str(evt.get("payload", {}))


class TestListModels:
    def test_returns_models(self):
        result = _invoke(_make_host(), "chp.adapters.mlx.list_models", {})
        assert result.success
        assert result.data["model_count"] == 1
        assert result.data["models"][0]["id"] == "mlx-community/Qwen3-4B-4bit"


# ---------------------------------------------------------------------------
# status — the "is MLX on this machine and serving?" check
# ---------------------------------------------------------------------------

class TestStatus:
    def test_reports_package_availability_and_healthy_server(self):
        result = _invoke(_make_host(), "chp.adapters.mlx.status", {})
        assert result.success
        d = result.data
        # Package availability is reported as booleans (value depends on the host env).
        assert isinstance(d["mlx_installed"], bool)
        assert isinstance(d["mlx_lm_installed"], bool)
        # The (fake) server is reachable.
        assert d["server_healthy"] is True
        assert d["model_count"] == 1
        assert d["server_url"] == "http://localhost:8081"

    def test_status_succeeds_even_when_server_down(self):
        result = _invoke(_make_host(server_up=False), "chp.adapters.mlx.status", {})
        assert result.success  # status never fails on an unreachable server
        assert result.data["server_healthy"] is False
        assert result.data["server_error"]


# ---------------------------------------------------------------------------
# start_server / stop_server — process lifecycle (mocked subprocess)
# ---------------------------------------------------------------------------

class TestServerLifecycle:
    def test_start_server_spawns_detached(self, monkeypatch, tmp_path):
        import chp_adapter_mlx.adapter as mod
        calls = {}

        class FakeProc:
            pid = 555

        monkeypatch.setattr(mod, "_run_dir", lambda: str(tmp_path))
        monkeypatch.setattr(mod.subprocess, "Popen",
                            lambda cmd, **kw: calls.update(cmd=cmd, kw=kw) or FakeProc())
        result = _invoke(_make_host(), "chp.adapters.mlx.start_server",
                         {"model": "mlx-community/Qwen3-4B-4bit", "port": 8081})
        assert result.success
        assert result.data["started"] is True
        assert result.data["pid"] == 555
        assert "--model" in calls["cmd"] and "mlx-community/Qwen3-4B-4bit" in calls["cmd"]
        assert "--port" in calls["cmd"] and "8081" in calls["cmd"]
        assert calls["kw"].get("start_new_session") is True
        # pidfile written
        assert (tmp_path / "mlx-server-8081.pid").exists()

    def test_start_server_idempotent_when_running(self, monkeypatch, tmp_path):
        import chp_adapter_mlx.adapter as mod
        monkeypatch.setattr(mod, "_run_dir", lambda: str(tmp_path))
        (tmp_path / "mlx-server-8081.pid").write_text(str(os.getpid()))  # a live pid (this test proc)
        called = {"popen": False}
        monkeypatch.setattr(mod.subprocess, "Popen",
                            lambda *a, **k: called.update(popen=True))
        result = _invoke(_make_host(), "chp.adapters.mlx.start_server", {"model": "m", "port": 8081})
        assert result.success
        assert result.data["already_running"] is True
        assert called["popen"] is False  # did not spawn a second server

    def test_start_server_requires_model(self):
        result = _invoke(_make_host(default_model=""), "chp.adapters.mlx.start_server", {})
        assert not result.success

    def test_stop_server_when_not_running(self, monkeypatch, tmp_path):
        import chp_adapter_mlx.adapter as mod
        monkeypatch.setattr(mod, "_run_dir", lambda: str(tmp_path))
        result = _invoke(_make_host(), "chp.adapters.mlx.stop_server", {"port": 8081})
        assert result.success
        assert result.data["stopped"] is False
        assert result.data["running"] is False


# ---------------------------------------------------------------------------
# Conformance — MLX adapter imports no HTTP library (composes via router)
# ---------------------------------------------------------------------------

class TestConformance:
    def test_adapter_has_no_violations(self):
        import inspect

        from chp_adapter_conformance import check_source_file
        import chp_adapter_mlx.adapter as mod

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"MLXAdapter has conformance violations: {violations}"
