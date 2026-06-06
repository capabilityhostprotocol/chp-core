"""Programmatic CHP evidence recording — AgentSession and wrap_tool_call.

Use these when you want CHP evidence from Python code without needing Claude Code hooks.

    with AgentSession(store_path=".chp/evidence.sqlite") as session:
        session.record_tool("read_file", {"path": "README.md"}, {"content": "..."})

    result = wrap_tool_call(
        "shell",
        {"command": "ls -la"},
        fn=lambda inp: subprocess.run(inp["command"], shell=True, capture_output=True),
    )
"""

from __future__ import annotations

from typing import Any, Callable

from .hooks import default_store_path, process_post_tool_use, process_pre_tool_use, process_stop
from .policy import PolicyConfig
from .store import SQLiteEvidenceStore
from .types import (
    AgentSessionDescriptor,
    CorrelationContext,
    ExecutionEvidence,
    new_id,
    utc_now,
)


def _emit_session_event(
    event_type: str,
    session_id: str,
    store_path: str,
    payload: dict[str, Any] | None = None,
) -> None:
    store = SQLiteEvidenceStore(store_path)
    store.append(
        ExecutionEvidence(
            event_id=new_id("ev"),
            event_type=event_type,
            invocation_id=new_id("inv"),
            capability_id="chp.session",
            capability_version=None,
            host_id="local",
            correlation=CorrelationContext(correlation_id=session_id),
            timestamp=utc_now(),
            outcome=None,
            payload=payload or {},
            redacted=False,
        )
    )
    store.close()


class AgentSession:
    """Context manager that records tool calls as CHP evidence.

    Emits ``agent_session_started`` on entry (when a descriptor is provided)
    and ``session_completed`` on exit regardless of whether an exception occurred.

    Usage::

        with AgentSession(store_path=".chp/evidence.sqlite") as session:
            session.record_tool("Bash", {"command": "ls"}, {"output": "...", "exit_code": 0})
            result = session.wrap("Read", {"file_path": "README.md"}, read_fn)

    With a descriptor::

        descriptor = AgentSessionDescriptor(
            session_id="sess-001",
            intent="Write tests for the memory module",
            model="claude-sonnet-4-6",
            autonomy_tier="supervised",
        )
        with AgentSession(descriptor=descriptor) as session:
            ...
    """

    def __init__(
        self,
        store_path: str | None = None,
        session_id: str | None = None,
        agent_prefix: str = "claude_code",
        tool_map: dict[str, str] | None = None,
        descriptor: AgentSessionDescriptor | None = None,
    ) -> None:
        self._descriptor = descriptor
        # descriptor.session_id takes precedence over the explicit session_id arg
        self._session_id = (
            descriptor.session_id if descriptor is not None else (session_id or new_id("session"))
        )
        self._store_path = store_path or default_store_path()
        self._agent_prefix = agent_prefix
        self._tool_map = tool_map

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def store_path(self) -> str:
        return self._store_path

    def __enter__(self) -> "AgentSession":
        if self._descriptor is not None:
            _emit_session_event(
                "agent_session_started",
                self._session_id,
                self._store_path,
                self._descriptor.to_dict(),
            )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        process_stop(
            {"session_id": self._session_id, "transcript_path": ""},
            self._store_path,
            agent_prefix=self._agent_prefix,
        )

    def record_tool(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_response: Any,
        cwd: str = "",
    ) -> None:
        """Record a completed tool call as a tool_use evidence event."""
        process_post_tool_use(
            {
                "session_id": self._session_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "tool_response": tool_response,
                "cwd": cwd,
            },
            self._store_path,
            tool_map=self._tool_map,
            agent_prefix=self._agent_prefix,
        )

    def wrap(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        fn: Callable[..., Any],
        cwd: str = "",
    ) -> Any:
        """Call fn(tool_input), record the outcome as evidence, and return the result.

        Records success on normal return, failure if fn raises. Re-raises the exception
        after recording so callers can handle it.
        """
        try:
            result = fn(tool_input)
        except Exception as exc:
            self.record_tool(tool_name, tool_input, {"error": str(exc)}, cwd=cwd)
            raise
        self.record_tool(tool_name, tool_input, result, cwd=cwd)
        return result


def wrap_tool_call(
    tool_name: str,
    tool_input: dict[str, Any],
    fn: Callable[..., Any],
    *,
    store_path: str | None = None,
    session_id: str | None = None,
    cwd: str = "",
    agent_prefix: str = "claude_code",
    tool_map: dict[str, str] | None = None,
    policy: PolicyConfig | None = None,
) -> Any:
    """One-shot wrapper: emit pre-tool evidence, call fn, emit post-tool evidence.

    Raises RuntimeError if a policy blocks the tool before fn is called.
    Re-raises any exception from fn after recording failure evidence.

    Args:
        tool_name: Name of the tool being called (e.g. "Bash", "shell").
        tool_input: Input dict passed to fn and stored in evidence.
        fn: Callable that receives tool_input and returns the result.
        store_path: Evidence store path. Defaults to default_store_path().
        session_id: Correlation ID. Defaults to a new unique session ID.
        cwd: Working directory for context; stored in evidence but not used for execution.
        agent_prefix: Capability ID prefix (default: "claude_code").
        tool_map: Optional tool-name → capability-ID mapping.
        policy: Optional pre-tool policy. Raises RuntimeError if the tool is blocked.
    """
    _store_path = store_path or default_store_path()
    _session_id = session_id or new_id("session")

    pre_payload: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": _session_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
    }
    result = process_pre_tool_use(
        pre_payload,
        _store_path,
        policy=policy,
        tool_map=tool_map,
        agent_prefix=agent_prefix,
    )
    if result.should_block:
        raise RuntimeError(f"CHP policy blocked tool '{tool_name}': {result.reason}")

    post_payload: dict[str, Any] = {
        "session_id": _session_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
    }

    try:
        fn_result = fn(tool_input)
    except Exception as exc:
        post_payload["tool_response"] = {"error": str(exc)}
        process_post_tool_use(post_payload, _store_path, tool_map=tool_map, agent_prefix=agent_prefix)
        raise

    post_payload["tool_response"] = fn_result if isinstance(fn_result, dict) else {"result": fn_result}
    process_post_tool_use(post_payload, _store_path, tool_map=tool_map, agent_prefix=agent_prefix)
    return fn_result
