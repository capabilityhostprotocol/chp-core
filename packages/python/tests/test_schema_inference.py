"""schema_from_type_hints + @capability(infer_schema=...) — opt-in type-hint schemas.

The one inference implementation lives in chp-core so every capability author can
reuse it (the CapabilityServer surface consumes it). It resolves stringized
annotations (PEP 563), skips ctx/payload/self, and is off by default so existing
capabilities are unchanged.
"""

from __future__ import annotations          # stringizes annotations (PEP 563)

from chp_core import capability, schema_from_type_hints
from chp_core.decorators import get_capability_descriptor


def test_helper_maps_type_hints_including_stringized():
    def fn(a: int, b: str, c: float, d: bool): ...
    assert schema_from_type_hints(fn) == {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "string"},
                       "c": {"type": "number"}, "d": {"type": "boolean"}},
        "required": ["a", "b", "c", "d"],  # no defaults -> all required
    }


def test_helper_marks_only_no_default_params_required():
    # A param WITH a default is optional (its default applies); one WITHOUT is required
    # (a missing value has no fallback -> deny at validation, not crash the handler).
    def fn(a: int, b: str = "x", c: float = 1.0): ...
    assert schema_from_type_hints(fn) == {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "string"},
                       "c": {"type": "number"}},
        "required": ["a"],
    }


def test_helper_skips_ctx_payload_self_and_varargs():
    def fn(self, ctx, payload, real: int, *args, **kwargs): ...
    assert schema_from_type_hints(fn) == {
        "type": "object", "properties": {"real": {"type": "integer"}},
        "required": ["real"]}


def test_helper_unannotated_is_unconstrained_and_empty_is_none():
    def fn(x): ...
    assert schema_from_type_hints(fn) == {
        "type": "object", "properties": {"x": {}}, "required": ["x"]}
    def nothing(): ...
    assert schema_from_type_hints(nothing) is None


def test_capability_infer_schema_opt_in():
    @capability(id="x.y", version="1.0.0", description="d", infer_schema=True)
    def h(a: int, b: str) -> dict:
        return {}
    assert get_capability_descriptor(h).input_schema == {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "string"}},
        "required": ["a", "b"]}


def test_capability_default_does_not_infer():
    @capability(id="x.z", version="1.0.0", description="d")
    def h(a: int) -> dict:
        return {}
    assert get_capability_descriptor(h).input_schema == {}   # unchanged behavior


def test_explicit_schema_wins_over_inference():
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    @capability(id="x.w", version="1.0.0", description="d",
                input_schema=schema, infer_schema=True)
    def h(a: int) -> dict:
        return {}
    assert get_capability_descriptor(h).input_schema == schema
