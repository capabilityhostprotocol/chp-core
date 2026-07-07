"""Tests for chp_adapter_http.adapter."""

from __future__ import annotations

import json

import httpx
import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_http import HttpAdapter, HttpConfig


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _make_transport(body: str = '{"ok": true}', status: int = 200,
                    content_type: str = "application/json"):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body.encode(),
                              headers={"content-type": content_type})
    return httpx.MockTransport(handler)


def _capturing_transport(capture: dict, body: str = '{"ok": true}', status: int = 200):
    def handler(req: httpx.Request) -> httpx.Response:
        capture["method"] = req.method
        capture["url"] = str(req.url)
        capture["headers"] = dict(req.headers)
        capture["body"] = req.content
        return httpx.Response(status, json={"ok": True})
    return httpx.MockTransport(handler)


def _make_host(config=None):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HttpAdapter(config))
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. Shaping
# --------------------------------------------------------------------------

class TestShaping:
    def test_one_capability(self):
        ids = {c.descriptor.id for c in HttpAdapter().capabilities()}
        assert ids == {"chp.adapters.http.request"}

    def test_medium_risk(self):
        caps = {c.descriptor.id: c.descriptor for c in HttpAdapter().capabilities()}
        assert caps["chp.adapters.http.request"].risk == "medium"


# --------------------------------------------------------------------------
# 2. Success path
# --------------------------------------------------------------------------

class TestSuccess:
    def test_get_returns_status_and_body(self):
        host = _make_host(HttpConfig(transport=_make_transport('{"hello": "world"}')))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/data"
        })
        assert r.outcome == "success"
        assert r.data["status_code"] == 200
        assert r.data["json"] == {"hello": "world"}
        assert r.data["body"] == '{"hello": "world"}'

    def test_post_with_json_body(self):
        capture: dict = {}
        host = _make_host(HttpConfig(transport=_capturing_transport(capture)))
        host.invoke("chp.adapters.http.request", {
            "method": "POST",
            "url": "https://api.example.com/items",
            "json_body": {"name": "widget"},
        })
        assert capture["method"] == "POST"
        assert json.loads(capture["body"]) == {"name": "widget"}

    def test_query_params_sent(self):
        capture: dict = {}
        host = _make_host(HttpConfig(transport=_capturing_transport(capture)))
        host.invoke("chp.adapters.http.request", {
            "method": "GET",
            "url": "https://api.example.com/search",
            "params": {"q": "hello", "limit": "10"},
        })
        assert "q=hello" in capture["url"]

    def test_custom_headers_sent(self):
        capture: dict = {}
        host = _make_host(HttpConfig(transport=_capturing_transport(capture)))
        host.invoke("chp.adapters.http.request", {
            "method": "GET",
            "url": "https://api.example.com/",
            "headers": {"X-Custom": "value"},
        })
        assert capture["headers"].get("x-custom") == "value"

    def test_default_headers_merged(self):
        capture: dict = {}
        host = _make_host(HttpConfig(
            default_headers={"X-App-Id": "app123"},
            transport=_capturing_transport(capture),
        ))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/"
        })
        assert capture["headers"].get("x-app-id") == "app123"

    def test_non_json_body_returned(self):
        host = _make_host(HttpConfig(
            transport=_make_transport("plain text response", content_type="text/plain")
        ))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://example.com/text"
        })
        assert r.data["body"] == "plain text response"
        assert r.data["json"] is None

    def test_4xx_response_succeeds_with_status(self):
        host = _make_host(HttpConfig(transport=_make_transport('{"error":"not found"}', status=404)))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/missing"
        })
        assert r.outcome == "success"
        assert r.data["status_code"] == 404


# --------------------------------------------------------------------------
# 3. URL allowlist
# --------------------------------------------------------------------------

class TestAllowlist:
    def test_url_outside_allowed_fails(self):
        host = _make_host(HttpConfig(
            allowed_origins=["https://api.allowed.com"],
            transport=_make_transport(),
        ))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://evil.com/steal"
        })
        assert r.outcome == "failure"

    def test_url_inside_allowed_succeeds(self):
        host = _make_host(HttpConfig(
            allowed_origins=["https://api.allowed.com"],
            transport=_make_transport(),
        ))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.allowed.com/v1/data"
        })
        assert r.outcome == "success"

    def test_no_allowlist_permits_all(self):
        host = _make_host(HttpConfig(
            allowed_origins=None,
            transport=_make_transport(),
        ))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://anywhere.example.com/path"
        })
        assert r.outcome == "success"

    def test_metadata_endpoint_blocked_even_without_allowlist(self):
        # SSRF crown jewel — denied by default, no allowlist required.
        host = _make_host(HttpConfig(allowed_origins=None, transport=_make_transport()))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "http://169.254.169.254/latest/meta-data/iam/",
        })
        assert r.outcome == "failure"

    def test_prefix_confusion_origin_not_admitted(self):
        # 'https://api.allowed.com' must NOT admit a look-alike sibling host.
        host = _make_host(HttpConfig(
            allowed_origins=["https://api.allowed.com"],
            transport=_make_transport(),
        ))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.allowed.com.attacker.net/x",
        })
        assert r.outcome == "failure"


# --------------------------------------------------------------------------
# 4. Schema validation
# --------------------------------------------------------------------------

class TestSchema:
    def test_missing_method_denied(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        r = host.invoke("chp.adapters.http.request", {"url": "https://x.com"})
        assert r.outcome == "denied"

    def test_missing_url_denied(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        r = host.invoke("chp.adapters.http.request", {"method": "GET"})
        assert r.outcome == "denied"

    def test_extra_field_denied(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        r = host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://x.com", "injected": "bad"
        })
        assert r.outcome == "denied"

    def test_invalid_method_denied(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        r = host.invoke("chp.adapters.http.request", {
            "method": "HACK", "url": "https://x.com"
        })
        assert r.outcome == "denied"


# --------------------------------------------------------------------------
# 5. Evidence hygiene
# --------------------------------------------------------------------------

class TestEvidenceHygiene:
    def test_response_body_not_in_evidence(self):
        host = _make_host(HttpConfig(transport=_make_transport('SECRET_RESPONSE_BODY_XYZ')))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/"
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "SECRET_RESPONSE_BODY_XYZ" not in dump

    def test_request_header_values_not_in_evidence(self):
        capture: dict = {}
        host = _make_host(HttpConfig(transport=_capturing_transport(capture)))
        host.invoke("chp.adapters.http.request", {
            "method": "GET",
            "url": "https://api.example.com/",
            "headers": {"Authorization": "Bearer SECRET_TOKEN_VALUE"},
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "SECRET_TOKEN_VALUE" not in dump

    def test_request_header_keys_in_evidence(self):
        capture: dict = {}
        host = _make_host(HttpConfig(transport=_capturing_transport(capture)))
        host.invoke("chp.adapters.http.request", {
            "method": "GET",
            "url": "https://api.example.com/",
            "headers": {"Authorization": "Bearer tok"},
        })
        dump = str([e["payload"] for e in _cap_events(host.store)])
        assert "Authorization" in dump or "authorization" in dump

    def test_http_request_event_emitted(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/"
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "http_request" in types

    def test_http_response_event_emitted(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/"
        })
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "http_response" in types

    def test_no_lifecycle_events_in_evidence(self):
        host = _make_host(HttpConfig(transport=_make_transport()))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/"
        })
        lifecycle = {"execution_started", "execution_completed", "execution_failed"}
        types = {e["event_type"] for e in _cap_events(host.store)}
        assert not types & lifecycle


# --------------------------------------------------------------------------
# 6. Resilience: retry + circuit breaker (transport-level failures only)
# --------------------------------------------------------------------------

def _failing_then_ok_transport(fail_count: int):
    state = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] <= fail_count:
            raise httpx.ConnectError("connection refused", request=req)
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler), state


class TestResilience:
    def test_retries_transport_error_then_succeeds(self):
        transport, state = _failing_then_ok_transport(2)
        host = _make_host(HttpConfig(transport=transport, max_retries=3, backoff_base=0.0))
        r = host.invoke("chp.adapters.http.request", {"method": "GET", "url": "http://svc.local/x"})
        assert r.outcome == "success"
        assert state["n"] == 3  # 2 failures + 1 success

    def test_exhausts_retries_then_fails(self):
        transport, _ = _failing_then_ok_transport(99)  # always fails
        host = _make_host(HttpConfig(transport=transport, max_retries=1, backoff_base=0.0))
        r = host.invoke("chp.adapters.http.request", {"method": "GET", "url": "http://svc.local/x"})
        assert r.outcome == "failure"
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "http_error" in types

    def test_circuit_opens_after_threshold_and_fails_fast(self):
        transport, state = _failing_then_ok_transport(99)
        host = _make_host(HttpConfig(
            transport=transport, max_retries=0, backoff_base=0.0,
            circuit_threshold=3, circuit_cooldown=60.0,
        ))
        for _ in range(3):
            host.invoke("chp.adapters.http.request", {"method": "GET", "url": "http://svc.local/x"})
        attempts_before = state["n"]
        # circuit now open → next call fails fast WITHOUT hitting the transport
        r = host.invoke("chp.adapters.http.request", {"method": "GET", "url": "http://svc.local/x"})
        assert r.outcome == "failure"
        assert "circuit open" in str(r.error).lower()
        assert state["n"] == attempts_before  # transport not invoked again
        types = [e["event_type"] for e in _cap_events(host.store)]
        assert "http_circuit_open" in types


# --------------------------------------------------------------------------
# 7. Token accounting
# --------------------------------------------------------------------------

def _usage_transport(prompt: int, completion: int, model: str = "test-model"):
    body = json.dumps({
        "choices": [{"message": {"content": "hello"}}],
        "model": model,
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    })
    return _make_transport(body)


class TestTokenAccounting:
    def test_token_fields_emitted_when_usage_present(self):
        host = _make_host(HttpConfig(transport=_usage_transport(10, 5)))
        host.invoke("chp.adapters.http.request", {
            "method": "POST", "url": "https://api.example.com/v1/chat/completions",
            "json_body": {"model": "test-model", "messages": []},
        })
        http_responses = [
            e for e in _cap_events(host.store) if e["event_type"] == "http_response"
        ]
        assert len(http_responses) == 1
        p = http_responses[0]["payload"]
        assert p["prompt_tokens"] == 10
        assert p["completion_tokens"] == 5
        assert p["total_tokens"] == 15
        assert p["model"] == "test-model"

    def test_token_fields_absent_when_no_usage(self):
        host = _make_host(HttpConfig(transport=_make_transport('{"result": "ok"}')))
        host.invoke("chp.adapters.http.request", {
            "method": "GET", "url": "https://api.example.com/health",
        })
        http_responses = [
            e for e in _cap_events(host.store) if e["event_type"] == "http_response"
        ]
        assert len(http_responses) == 1
        p = http_responses[0]["payload"]
        assert "prompt_tokens" not in p
        assert "completion_tokens" not in p
        assert "model" not in p

    def test_model_extracted_from_request_body(self):
        # Response has usage but no model field → fall back to json_body.model
        body = json.dumps({
            "choices": [],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2},
        })
        host = _make_host(HttpConfig(transport=_make_transport(body)))
        host.invoke("chp.adapters.http.request", {
            "method": "POST", "url": "https://api.example.com/v1/chat/completions",
            "json_body": {"model": "req-body-model", "messages": []},
        })
        http_responses = [
            e for e in _cap_events(host.store) if e["event_type"] == "http_response"
        ]
        p = http_responses[0]["payload"]
        assert p["model"] == "req-body-model"
        assert p["prompt_tokens"] == 8
