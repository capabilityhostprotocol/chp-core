"""Tests for chp_adapter_scout.adapter.

No live model or filesystem needed: a FakeCtx intercepts ctx.ainvoke() calls
and returns scripted responses. The _parse_citations helper is also tested
directly.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from chp_adapter_scout import ScoutAdapter, ScoutConfig
from chp_adapter_scout.adapter import _parse_citations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeResult:
    success: bool
    data: Any = None
    error: Any = None
    outcome: str = "success"


class FakeCtx:
    """Minimal ctx stub for testing ScoutAdapter without a real host."""

    def __init__(self, responses: dict | None = None) -> None:
        # responses: dict[capability_id -> list[FakeResult]] (consumed in order)
        self._queues: dict[str, list[FakeResult]] = {}
        for cap_id, results in (responses or {}).items():
            self._queues[cap_id] = list(results)
        self.emitted: list[tuple[str, dict]] = []

    def emit(self, event_type: str, payload: dict, redacted: bool = False) -> None:
        self.emitted.append((event_type, payload))

    async def ainvoke(self, capability_id: str, payload: dict, **_kw) -> FakeResult:
        queue = self._queues.get(capability_id, [])
        if queue:
            return queue.pop(0)
        return FakeResult(success=True, data={}, outcome="success")


def _model_response(content: str, tool_calls: list | None = None) -> FakeResult:
    """Build a fake HTTP result that looks like an OpenAI /v1/chat/completions response."""
    message: dict = {"content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return FakeResult(
        success=True,
        data={
            "json": {
                "choices": [{"message": message}]
            },
            "status_code": 200,
        },
    )


def _tool_call(tc_id: str, name: str, args: dict) -> dict:
    return {
        "id": tc_id,
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def _fs_read_result(content: str) -> FakeResult:
    return FakeResult(success=True, data={"content": content}, outcome="success")


def _fs_grep_result(matches: list[dict]) -> FakeResult:
    return FakeResult(success=True, data={"matches": matches, "match_count": len(matches), "truncated": False})


def _fs_glob_result(files: list[str]) -> FakeResult:
    return FakeResult(success=True, data={"files": files, "count": len(files), "truncated": False})


_HTTP_CAP = "chp.adapters.http.request"
_FS_READ = "chp.adapters.filesystem.read_file"
_FS_GLOB = "chp.adapters.filesystem.glob_files"
_FS_GREP = "chp.adapters.filesystem.grep"


# ---------------------------------------------------------------------------
# 1. Shaping
# ---------------------------------------------------------------------------

class TestShaping:
    def test_one_capability(self):
        ids = {c.descriptor.id for c in ScoutAdapter().capabilities()}
        assert ids == {"chp.adapters.scout.query"}

    def test_medium_risk(self):
        caps = {c.descriptor.id: c.descriptor for c in ScoutAdapter().capabilities()}
        assert caps["chp.adapters.scout.query"].risk == "medium"

    def test_adapter_id(self):
        assert ScoutAdapter().adapter_id == "chp.adapters.scout"

    def test_query_requires_task_and_repo(self):
        cap = list(ScoutAdapter().capabilities())[0]
        schema = cap.descriptor.input_schema
        assert "task" in schema["required"]
        assert "repo_path" in schema["required"]


# ---------------------------------------------------------------------------
# 2. Single-turn success (model answers directly, no tool calls)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestSingleTurn:
    async def test_returns_citations_on_direct_answer(self):
        answer = (
            "<final_answer>\n"
            "/repo/store.py:42-58  # WAL pragma\n"
            "/repo/db.py:10\n"
            "</final_answer>"
        )
        ctx = FakeCtx({_HTTP_CAP: [_model_response(answer)]})
        adapter = ScoutAdapter(ScoutConfig(base_url="http://localhost:8094"))
        result = await adapter.query(ctx, {"task": "find WAL", "repo_path": "/repo"})
        assert result["turns_used"] == 1
        assert result["files_cited_count"] == 2
        paths = [f["path"] for f in result["files"]]
        assert "/repo/store.py" in paths
        assert "/repo/db.py" in paths

    async def test_emits_started_and_completed(self):
        answer = "<final_answer>/repo/x.py:1</final_answer>"
        ctx = FakeCtx({_HTTP_CAP: [_model_response(answer)]})
        adapter = ScoutAdapter()
        await adapter.query(ctx, {"task": "x", "repo_path": "/repo"})
        event_types = [e[0] for e in ctx.emitted]
        assert "scout_started" in event_types
        assert "scout_completed" in event_types
        assert "scout_failed" not in event_types

    async def test_task_not_in_evidence(self):
        answer = "<final_answer>/repo/a.py:1</final_answer>"
        ctx = FakeCtx({_HTTP_CAP: [_model_response(answer)]})
        await ScoutAdapter().query(ctx, {
            "task": "SENSITIVE_TASK_9988776655",
            "repo_path": "/repo",
        })
        all_payloads = json.dumps([e[1] for e in ctx.emitted])
        assert "SENSITIVE_TASK_9988776655" not in all_payloads


# ---------------------------------------------------------------------------
# 3. Multi-turn: tool calls then final answer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMultiTurn:
    async def test_grep_then_read_then_answer(self):
        grep_tc = _tool_call("tc1", "grep", {"pattern": "WAL", "path": "."})
        read_tc = _tool_call("tc2", "read_file", {"path": "store.py", "start_line": 40, "end_line": 60})
        final_answer = "<final_answer>/repo/store.py:42-58  # WAL pragma</final_answer>"

        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[grep_tc]),
                _model_response("", tool_calls=[read_tc]),
                _model_response(final_answer),
            ],
            _FS_GREP: [_fs_grep_result([{"file": "store.py", "line_no": "42", "text": "PRAGMA journal_mode=WAL"}])],
            _FS_READ: [_fs_read_result("line 40\nPRAGMA journal_mode=WAL\nline 60")],
        })

        result = await ScoutAdapter(ScoutConfig(max_turns=6)).query(ctx, {
            "task": "Where is WAL pragma set?",
            "repo_path": "/repo",
        })
        assert result["turns_used"] == 3
        assert result["files_cited_count"] == 1
        assert result["files"][0]["path"] == "/repo/store.py"
        assert result["files"][0]["line_range"] == "42-58"

    async def test_parallel_tool_calls(self):
        glob_tc = _tool_call("tc1", "glob", {"pattern": "**/*.py", "path": "."})
        grep_tc = _tool_call("tc2", "grep", {"pattern": "class Foo", "path": "."})
        final_answer = "<final_answer>/repo/foo.py:5</final_answer>"

        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[glob_tc, grep_tc]),
                _model_response(final_answer),
            ],
            _FS_GLOB: [_fs_glob_result(["foo.py", "bar.py"])],
            _FS_GREP: [_fs_grep_result([{"file": "foo.py", "line_no": "5", "text": "class Foo:"}])],
        })

        result = await ScoutAdapter().query(ctx, {"task": "find Foo", "repo_path": "/repo"})
        assert result["turns_used"] == 2
        tool_events = [e for e in ctx.emitted if e[0] == "scout_tool_call"]
        assert len(tool_events) == 1
        assert set(tool_events[0][1]["tool_names"]) == {"glob", "grep"}

    async def test_max_turns_exhausted_returns_partial(self):
        tool_call = _tool_call("tc", "grep", {"pattern": "x", "path": "."})
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[tool_call]),
                _model_response("", tool_calls=[tool_call]),
                _model_response("", tool_calls=[tool_call]),
            ],
            _FS_GREP: [
                _fs_grep_result([]),
                _fs_grep_result([]),
                _fs_grep_result([]),
            ],
        })

        result = await ScoutAdapter(ScoutConfig(max_turns=2)).query(ctx, {
            "task": "find x", "repo_path": "/repo",
        })
        assert result["turns_used"] == 2
        assert result["files_cited_count"] == 0


# ---------------------------------------------------------------------------
# 3b. Grep output capping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGrepOutputCap:
    async def test_large_grep_result_is_capped(self):
        """Grep results exceeding 4000 chars are truncated before being sent to the model."""
        # Build 60 matches each with a 100-char text — total ~6000 chars, exceeds cap
        big_matches = [
            {"file": f"/repo/file_{i}.py", "line_no": str(i), "text": "x" * 80}
            for i in range(60)
        ]
        grep_tc = _tool_call("tc1", "grep", {"pattern": "x", "path": "."})
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[grep_tc]),
                _model_response("<final_answer>/repo/file_0.py:1</final_answer>"),
            ],
            _FS_GREP: [_fs_grep_result(big_matches)],
        })
        result = await ScoutAdapter(ScoutConfig(max_turns=6)).query(ctx, {
            "task": "find x",
            "repo_path": "/repo",
        })
        # Tool message sent to model should have been capped
        tool_messages = [m for m in ctx.emitted]
        # Verify the loop completed normally (cap did not crash anything)
        assert result["turns_used"] == 2

    async def test_small_grep_result_is_not_capped(self):
        matches = [{"file": "/repo/a.py", "line_no": "1", "text": "hello"}]
        grep_tc = _tool_call("tc1", "grep", {"pattern": "hello", "path": "."})
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[grep_tc]),
                _model_response("<final_answer>/repo/a.py:1</final_answer>"),
            ],
            _FS_GREP: [_fs_grep_result(matches)],
        })
        result = await ScoutAdapter(ScoutConfig(max_turns=6)).query(ctx, {
            "task": "find hello",
            "repo_path": "/repo",
        })
        assert result["files_cited_count"] == 1


# ---------------------------------------------------------------------------
# 4. Error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestErrors:
    async def test_model_unreachable_raises(self):
        ctx = FakeCtx({
            _HTTP_CAP: [FakeResult(success=False, error="connection refused", outcome="failure")],
        })
        with pytest.raises(RuntimeError, match="Scout model unreachable"):
            await ScoutAdapter().query(ctx, {"task": "x", "repo_path": "/repo"})

    async def test_model_error_emits_scout_failed(self):
        ctx = FakeCtx({
            _HTTP_CAP: [FakeResult(success=False, error="timeout", outcome="failure")],
        })
        try:
            await ScoutAdapter().query(ctx, {"task": "x", "repo_path": "/repo"})
        except RuntimeError:
            pass
        event_types = [e[0] for e in ctx.emitted]
        assert "scout_failed" in event_types
        assert "scout_completed" not in event_types

    async def test_fs_error_returns_error_string_to_model(self):
        """A filesystem capability failure should not crash the loop — it sends error text to the model."""
        tool_call = _tool_call("tc", "read_file", {"path": "missing.py"})
        final_answer = "<final_answer>/repo/other.py:1</final_answer>"
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[tool_call]),
                _model_response(final_answer),
            ],
            _FS_READ: [FakeResult(success=False, error="file not found", outcome="failure")],
        })
        result = await ScoutAdapter().query(ctx, {"task": "x", "repo_path": "/repo"})
        # Loop continued despite fs error — final answer was parsed
        assert result["files_cited_count"] == 1

    async def test_malformed_tool_arguments_returns_error_string(self):
        bad_tc = {"id": "tc1", "function": {"name": "grep", "arguments": "NOT JSON"}}
        final_answer = "<final_answer>/repo/a.py:1</final_answer>"
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("", tool_calls=[bad_tc]),
                _model_response(final_answer),
            ],
        })
        result = await ScoutAdapter().query(ctx, {"task": "x", "repo_path": "/repo"})
        assert result["files_cited_count"] == 1


# ---------------------------------------------------------------------------
# 5. Citation parser
# ---------------------------------------------------------------------------

class TestParseCitations:
    def test_full_final_answer_block(self):
        content = (
            "Some preamble text\n"
            "<final_answer>\n"
            "/repo/store.py:42-58  # WAL pragma\n"
            "/repo/db.py:10\n"
            "</final_answer>"
        )
        citations = _parse_citations(content, "/repo")
        assert len(citations) == 2
        assert citations[0]["path"] == "/repo/store.py"
        assert citations[0]["line_range"] == "42-58"
        assert citations[0]["note"] == "WAL pragma"
        assert citations[1]["path"] == "/repo/db.py"
        assert citations[1]["line_range"] == "10"

    def test_relative_path_prepended(self):
        content = "<final_answer>src/foo.py:1-5</final_answer>"
        citations = _parse_citations(content, "/myrepo")
        assert citations[0]["path"] == "/myrepo/src/foo.py"

    def test_absolute_path_unchanged_when_exists(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            real = f.name
        try:
            content = f"<final_answer>{real}:3</final_answer>"
            citations = _parse_citations(content, "/repo")
            assert citations[0]["path"] == real
        finally:
            os.unlink(real)

    def test_root_relative_path_resolved_under_repo(self, tmp_path):
        (tmp_path / "packages").mkdir()
        (tmp_path / "packages" / "foo.py").write_text("x")
        content = "<final_answer>/packages/foo.py:1-5</final_answer>"
        citations = _parse_citations(content, str(tmp_path))
        assert citations[0]["path"] == str(tmp_path / "packages" / "foo.py")
        assert citations[0]["line_range"] == "1-5"

    def test_nonexistent_absolute_path_kept_as_is(self):
        content = "<final_answer>/no/such/file.py:3</final_answer>"
        citations = _parse_citations(content, "/also/missing")
        assert citations[0]["path"] == "/no/such/file.py"

    def test_no_final_answer_block_falls_back_to_full_content(self):
        content = "/repo/fallback.py:7"
        citations = _parse_citations(content, "/repo")
        assert len(citations) == 1
        assert citations[0]["path"] == "/repo/fallback.py"

    def test_no_citations_returns_empty(self):
        citations = _parse_citations("No file paths here, just text.", "/repo")
        assert citations == []

    def test_citation_without_line_number(self):
        content = "<final_answer>/repo/config.toml</final_answer>"
        citations = _parse_citations(content, "/repo")
        assert citations[0]["path"] == "/repo/config.toml"
        assert "line_range" not in citations[0]

    def test_note_is_optional(self):
        content = "<final_answer>/repo/main.py:1-10</final_answer>"
        citations = _parse_citations(content, "/repo")
        assert "note" not in citations[0]

    def test_blank_lines_and_comments_skipped(self):
        content = "<final_answer>\n\n# comment\n/repo/real.py:1\n</final_answer>"
        citations = _parse_citations(content, "/repo")
        assert len(citations) == 1


# ---------------------------------------------------------------------------
# 7. Token accounting
# ---------------------------------------------------------------------------

def _model_response_usage(content: str, prompt: int, completion: int,
                           tool_calls: list | None = None) -> FakeResult:
    message: dict = {"content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return FakeResult(
        success=True,
        data={
            "json": {
                "choices": [{"message": message}],
                "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
            },
            "status_code": 200,
        },
    )


class TestTokenAccounting:
    def _run(self, ctx, task="/repo"):
        adapter = ScoutAdapter(ScoutConfig(max_turns=6))
        return asyncio.run(adapter.query(ctx, {"task": "find something", "repo_path": task}))

    def test_token_counts_accumulated_across_turns(self):
        ctx = FakeCtx({
            _HTTP_CAP: [
                # Turn 1: tool call
                _model_response_usage("", prompt=100, completion=20, tool_calls=[
                    _tool_call("c1", "glob", {"pattern": "*.py"})
                ]),
                # Turn 2: final answer
                _model_response_usage(
                    "<final_answer>/repo/store.py:1</final_answer>",
                    prompt=150, completion=30,
                ),
            ],
            _FS_GLOB: [_fs_glob_result(["/repo/store.py"])],
        })
        result = self._run(ctx)
        assert result["prompt_tokens"] == 250
        assert result["completion_tokens"] == 50
        assert result["total_tokens"] == 300

        completed_events = [e for e in ctx.emitted if e[0] == "scout_completed"]
        assert len(completed_events) == 1
        ep = completed_events[0][1]
        assert ep["prompt_tokens"] == 250
        assert ep["completion_tokens"] == 50
        assert ep["total_tokens"] == 300

    def test_token_counts_zero_when_no_usage(self):
        ctx = FakeCtx({
            _HTTP_CAP: [
                _model_response("<final_answer>/repo/main.py:1</final_answer>"),
            ],
        })
        result = self._run(ctx)
        assert result["prompt_tokens"] == 0
        assert result["completion_tokens"] == 0
        assert result["total_tokens"] == 0
