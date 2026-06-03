"""Property-based tests for CHP protocol invariants using Hypothesis.

These tests verify that core functions never crash and respect structural
invariants regardless of what input they receive.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hypothesis import given, settings
from hypothesis import strategies as st

from chp_core.hooks import capability_id_for_tool
from chp_core.redaction import redact_payload


class CapabilityIdMappingProperties(unittest.TestCase):
    @given(st.text())
    def test_never_raises_on_any_input(self, tool_name: str) -> None:
        result = capability_id_for_tool(tool_name)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    @given(st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_")))
    def test_result_is_always_a_non_empty_string(self, tool_name: str) -> None:
        result = capability_id_for_tool(tool_name)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    @given(
        st.text(min_size=1, alphabet="abcdefghijklmnopqrstuvwxyz_"),
        st.text(min_size=1, alphabet="abcdefghijklmnopqrstuvwxyz_"),
        st.text(min_size=1, alphabet="abcdefghijklmnopqrstuvwxyz_"),
    )
    def test_mcp_tools_produce_dotted_capability_id(self, prefix: str, server: str, tool: str) -> None:
        tool_name = f"mcp__{server}__{tool}"
        result = capability_id_for_tool(tool_name)
        self.assertTrue(result.startswith("claude_code.mcp."))

    @given(st.from_regex(r"[A-Za-z0-9_]+", fullmatch=True))
    def test_result_contains_no_whitespace_for_valid_tool_names(self, tool_name: str) -> None:
        # Real Claude Code tool names only contain alphanumeric + underscore characters
        result = capability_id_for_tool(tool_name)
        self.assertNotIn(" ", result)
        self.assertNotIn("\n", result)
        self.assertNotIn("\t", result)


class RedactionProperties(unittest.TestCase):
    @given(st.dictionaries(st.text(), st.text()))
    def test_never_crashes_on_any_dict(self, payload: dict) -> None:
        result = redact_payload(payload)
        self.assertIsInstance(result, dict)

    @given(st.dictionaries(st.text(), st.text()))
    def test_preserves_all_keys(self, payload: dict) -> None:
        result = redact_payload(payload)
        self.assertEqual(set(result.keys()), set(payload.keys()))

    @given(st.dictionaries(st.text(), st.text()))
    @settings(max_examples=50)
    def test_idempotent(self, payload: dict) -> None:
        once = redact_payload(payload)
        twice = redact_payload(once)
        self.assertEqual(once, twice)

    @given(
        st.sampled_from(["api_key", "authorization", "password", "secret", "token", "access_token", "cookie"]),
        st.text(min_size=1),
    )
    def test_known_sensitive_keys_are_redacted(self, key: str, value: str) -> None:
        result = redact_payload({key: value})
        self.assertEqual(result[key], "[REDACTED]")

    @given(
        st.text(min_size=1).filter(
            # Redaction uses substring matching — exclude any key containing a sensitive substring
            lambda k: not any(
                s in k.lower()
                for s in ("api_key", "authorization", "password", "secret", "token", "cookie")
            )
        ),
        st.text(),
    )
    def test_non_sensitive_keys_pass_through(self, key: str, value: str) -> None:
        result = redact_payload({key: value})
        self.assertEqual(result[key], value)


if __name__ == "__main__":
    unittest.main()
