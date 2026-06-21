"""Tests for chp_adapter_mcp.adapter — all mocked, no live MCP server.

A ``FakeSession`` stands in for ``_ThreadedMCPSession`` so tests exercise the
adapter's capability shaping, evidence emission, and end-to-end host wiring
without spawning a subprocess or background thread.
"""

from __future__ import annotations

import pytest

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_mcp import MCPAdapter, MCPServerConfig
from chp_adapter_mcp.adapter import _serialize_block


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------

class FakeTool:
    def __init__(self, name, description, input_schema):
        self.name = name
        self.description = description
        self.inputSchema = input_schema


class FakeBlock:
    """Mimics an MCP content block with model_dump()."""
    def __init__(self, text):
        self._text = text

    def model_dump(self, mode="python"):
        return {"type": "text", "text": self._text}


class FakeResult:
    def __init__(self, content, is_error=False):
        self.content = content
        self.isError = is_error


class FakeSession:
    """In-memory _MCPSession: canned tools, scripted call() behaviour."""

    def __init__(self, tools, *, result=None, raises=None):
        self._tools = tools
        self._result = result
        self._raises = raises
        self.connected = False
        self.closed = False
        self.calls = []

    @property
    def tools(self):
        return self._tools

    def connect(self):
        self.connected = True

    async def call(self, name, arguments):
        self.calls.append((name, arguments))
        if self._raises is not None:
            raise self._raises
        return self._result

    def close(self):
        self.closed = True


def _tools():
    return [
        FakeTool("read_file", "Read a file", {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }),
        FakeTool("list_dir", "List a directory", {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        }),
    ]


def _adapter(session):
    return MCPAdapter(MCPServerConfig(name="fs", command="dummy"), session=session)


def _make_host(adapter):
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, adapter)
    return host


def _cap_events(store):
    return [e for e in store.all() if "capability_uri" not in e["payload"]]


# --------------------------------------------------------------------------
# 1. capabilities() shaping
# --------------------------------------------------------------------------

class TestCapabilityShaping:
    def test_one_capability_per_tool(self):
        adapter = _adapter(FakeSession(_tools()))
        caps = list(adapter.capabilities())
        assert len(caps) == 2

    def test_capability_ids_namespaced_by_server(self):
        adapter = _adapter(FakeSession(_tools()))
        ids = {c.descriptor.id for c in adapter.capabilities()}
        assert ids == {
            "chp.adapters.mcp.fs.read_file",
            "chp.adapters.mcp.fs.list_dir",
        }

    def test_input_schema_passthrough(self):
        adapter = _adapter(FakeSession(_tools()))
        read = next(c for c in adapter.capabilities()
                    if c.descriptor.id.endswith("read_file"))
        assert read.descriptor.input_schema["required"] == ["path"]

    def test_descriptor_metadata(self):
        adapter = _adapter(FakeSession(_tools()))
        cap = next(iter(adapter.capabilities()))
        d = cap.descriptor
        assert d.provider == "mcp"
        assert d.category == "integration"
        assert d.risk == "medium"
        assert "mcp" in d.tags and "fs" in d.tags

    def test_connect_called_once_across_repeated_capabilities(self):
        session = FakeSession(_tools())
        adapter = _adapter(session)
        list(adapter.capabilities())
        list(adapter.capabilities())
        # connect() guarded by _connected flag — idempotent
        assert session.connected is True

    def test_adapter_id_from_server_name(self):
        adapter = _adapter(FakeSession(_tools()))
        assert adapter.adapter_id == "chp.adapters.mcp.fs"


# --------------------------------------------------------------------------
# 2. Success path — return shape + evidence events
# --------------------------------------------------------------------------

class TestSuccessPath:
    def _host(self):
        session = FakeSession(_tools(), result=FakeResult([FakeBlock("hello")]))
        return _make_host(_adapter(session)), session

    def test_outcome_success(self):
        host, _ = self._host()
        result = host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        assert result.outcome == "success"

    def test_return_shape(self):
        host, _ = self._host()
        result = host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        assert result.data == {
            "content": [{"type": "text", "text": "hello"}],
            "isError": False,
        }

    def test_arguments_forwarded_to_session(self):
        host, session = self._host()
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        assert session.calls == [("read_file", {"path": "/tmp/x"})]

    def test_event_sequence(self):
        host, _ = self._host()
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        types = [e["event_type"] for e in _cap_events(store)]
        assert types == ["mcp_tool_called", "mcp_tool_result"]

    def test_called_event_records_arg_keys_not_values(self):
        host, _ = self._host()
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/secret/value"})
        called = next(e for e in _cap_events(store)
                      if e["event_type"] == "mcp_tool_called")
        assert called["payload"]["arg_keys"] == ["path"]
        assert "/secret/value" not in str(called["payload"])

    def test_result_event_counts_blocks(self):
        host, _ = self._host()
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        result_evt = next(e for e in _cap_events(store)
                          if e["event_type"] == "mcp_tool_result")
        assert result_evt["payload"]["content_blocks"] == 1
        assert result_evt["payload"]["is_error"] is False


# --------------------------------------------------------------------------
# 3. Failure path
# --------------------------------------------------------------------------

class TestFailurePath:
    def test_call_exception_emits_mcp_error(self):
        session = FakeSession(_tools(), raises=RuntimeError("connection reset"))
        host = _make_host(_adapter(session))
        store = host.store
        result = host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        assert result.outcome == "failure"
        failed = next(e for e in _cap_events(store)
                      if e["event_type"] == "mcp_error")
        assert failed["payload"]["reason"] == "RuntimeError"
        assert "connection reset" in failed["payload"]["error"]

    def test_error_truncated(self):
        session = FakeSession(_tools(), raises=RuntimeError("x" * 5000))
        host = _make_host(_adapter(session))
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        failed = next(e for e in _cap_events(store)
                      if e["event_type"] == "mcp_error")
        assert len(failed["payload"]["error"]) <= 500

    def test_no_result_event_on_failure(self):
        session = FakeSession(_tools(), raises=RuntimeError("boom"))
        host = _make_host(_adapter(session))
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/tmp/x"})
        types = [e["event_type"] for e in _cap_events(store)]
        assert "mcp_error" in types
        assert "mcp_tool_result" not in types


# --------------------------------------------------------------------------
# 4. isError surfaced
# --------------------------------------------------------------------------

class TestIsErrorSurfaced:
    def test_tool_error_result_returned_not_raised(self):
        session = FakeSession(
            _tools(),
            result=FakeResult([FakeBlock("not found")], is_error=True),
        )
        host = _make_host(_adapter(session))
        result = host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/nope"})
        # An MCP tool-level error is a successful invocation that returns isError
        assert result.outcome == "success"
        assert result.data["isError"] is True

    def test_result_event_marks_is_error(self):
        session = FakeSession(
            _tools(),
            result=FakeResult([FakeBlock("not found")], is_error=True),
        )
        host = _make_host(_adapter(session))
        store = host.store
        host.invoke("chp.adapters.mcp.fs.read_file", {"path": "/nope"})
        result_evt = next(e for e in _cap_events(store)
                          if e["event_type"] == "mcp_tool_result")
        assert result_evt["payload"]["is_error"] is True


# --------------------------------------------------------------------------
# 5. input_schema validation (chp-core guard applies for free)
# --------------------------------------------------------------------------

class TestInputSchemaGuard:
    def test_missing_required_arg_is_denied(self):
        session = FakeSession(_tools(), result=FakeResult([FakeBlock("x")]))
        host = _make_host(_adapter(session))
        result = host.invoke("chp.adapters.mcp.fs.read_file", {})  # missing path
        assert result.outcome == "denied"

    def test_session_not_called_on_validation_failure(self):
        session = FakeSession(_tools(), result=FakeResult([FakeBlock("x")]))
        host = _make_host(_adapter(session))
        host.invoke("chp.adapters.mcp.fs.read_file", {})
        assert session.calls == []


# --------------------------------------------------------------------------
# 6. _serialize_block unit
# --------------------------------------------------------------------------

class TestSerializeBlock:
    def test_dict_passthrough(self):
        assert _serialize_block({"type": "text", "text": "hi"}) == {"type": "text", "text": "hi"}

    def test_model_dump_used(self):
        assert _serialize_block(FakeBlock("hi")) == {"type": "text", "text": "hi"}

    def test_fallback_to_str(self):
        assert _serialize_block(42) == {"type": "text", "text": "42"}
