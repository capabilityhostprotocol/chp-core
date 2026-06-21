"""smolagents backend — the only file that imports smolagents.

Isolated here so adapter.py stays free of the smolagents dependency and can be
unit-tested with an injected fake backend (no LLM, no agent execution).

The adapter supplies plain sync callables (each bridging to a CHP capability via
the host router); this module wraps them as smolagents Tools, builds the model,
and runs a CodeAgent.
"""

from __future__ import annotations

from typing import Any, Callable


def make_tool(name: str, description: str, func: Callable[[dict], Any]) -> Any:
    """Wrap a sync callable as a smolagents Tool that takes a single ``payload`` dict."""
    from smolagents import Tool

    class _CHPTool(Tool):
        # smolagents reads these as class attributes
        pass

    tool = _CHPTool.__new__(_CHPTool)
    tool.name = name
    tool.description = description
    tool.inputs = {
        "payload": {
            "type": "object",
            "description": "JSON object passed as the CHP capability payload.",
        }
    }
    tool.output_type = "object"
    # Bind forward to delegate to the bridge callable
    tool.forward = lambda payload: func(payload)  # type: ignore[assignment]
    tool.is_initialized = True
    return tool


def build_model(model_type: str, model_id: str, api_base: str, api_key: str) -> Any:
    """Construct a smolagents model from config."""
    if model_type == "openai_server":
        from smolagents import OpenAIServerModel

        return OpenAIServerModel(model_id=model_id, api_base=api_base, api_key=api_key or "EMPTY")
    if model_type == "mlx":
        from smolagents import MLXModel

        return MLXModel(model_id=model_id)
    if model_type == "transformers":
        from smolagents import TransformersModel

        return TransformersModel(model_id=model_id)
    raise ValueError(f"Unknown model_type: {model_type!r}. Use 'openai_server', 'mlx', or 'transformers'.")


def run_agent(model: Any, tools: list[Any], task: str, max_steps: int) -> dict:
    """Run a CodeAgent on the task and return answer + step count."""
    from smolagents import CodeAgent

    agent = CodeAgent(tools=tools, model=model, max_steps=max_steps)
    answer = agent.run(task)

    steps = 0
    try:
        steps = len([s for s in agent.memory.steps if type(s).__name__ == "ActionStep"])
    except Exception:
        steps = 0

    return {"answer": str(answer), "steps": steps}
