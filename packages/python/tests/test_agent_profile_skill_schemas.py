"""Canonical AgentProfile + Skill schemas (chp-viewer catalog Phase 2, rad:407beb7a).

Proves the new v0.3 profile-family schemas accept real chp-agentkit output — including nested skills
and a recursive `managed` sub-profile resolved by $ref — and fail closed on drift (unknown fields).
The example instances under schemas/examples/ are generated from the chp-agentkit dataclasses.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "schemas"
EXAMPLES = SCHEMA_DIR / "examples"


class AgentProfileSkillSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.name: json.loads(path.read_text())
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        }
        # A registry over every schema so agent-profile's external $ref to skill (and its recursive
        # self-$ref for `managed`) resolve by $id.
        cls.registry = Registry().with_resources(
            [(s["$id"], Resource.from_contents(s)) for s in cls.schemas.values()]
        )

    def _validator(self, name: str) -> Draft202012Validator:
        return Draft202012Validator(self.schemas[name], registry=self.registry)

    def test_schemas_present_and_valid(self) -> None:
        for name in ("skill.schema.json", "agent-profile.schema.json"):
            self.assertIn(name, self.schemas)
            Draft202012Validator.check_schema(self.schemas[name])
        self.assertEqual(self.schemas["skill.schema.json"]["title"], "Skill")
        self.assertEqual(self.schemas["agent-profile.schema.json"]["title"], "AgentProfile")

    def test_real_agentkit_examples_validate(self) -> None:
        self._validator("skill.schema.json").validate(
            json.loads((EXAMPLES / "skill.example.json").read_text())
        )
        # The profile carries a nested skill AND a recursive `managed` sub-profile.
        profile = json.loads((EXAMPLES / "agent-profile.example.json").read_text())
        self._validator("agent-profile.schema.json").validate(profile)
        self.assertTrue(profile["managed"], "example must exercise the recursive managed $ref")
        self.assertTrue(profile["managed"][0]["skills"], "managed sub must carry a nested skill")

    def test_fail_closed_on_unknown_field(self) -> None:
        from jsonschema import ValidationError

        bad = json.loads((EXAMPLES / "skill.example.json").read_text())
        bad["typo_field"] = 1
        with self.assertRaises(ValidationError):
            self._validator("skill.schema.json").validate(bad)


if __name__ == "__main__":
    unittest.main()
