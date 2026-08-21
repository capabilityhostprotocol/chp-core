"""CapabilityDefinition + relationship algebra (proposal 0045, Tier C).

Proves the semantic definition serializes under schema, off-enum relationship/effect is
rejected, and the algebra's restraint holds: a declared relationship alone never grants
substitution without explicit policy, compatible_with is neither transitive nor substitutable,
and similarity is not a relationship at all (CHP-CAP-009/015/017/018/019).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import CapabilityDefinition, CapabilityRelationship

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/capability-definition.schema.json").read_text()
)


def test_definition_serializes_under_schema():
    d = CapabilityDefinition(
        id="org.chp.database.schema.migrate",
        version="1.0.0",
        namespace={"authority": {"id": "urn:chp:authority:chp"}},
        description="Apply a database schema migration.",
        input_schema={"type": "object"},
        effect={"class": "transactional"},
        relationships=[{"type": "supersedes", "target": {"id": "org.chp.database.migrate", "version": "0.9.0"}}],
    )
    jsonschema.validate(d.to_dict(), _SCHEMA)


def test_off_enum_relationship_and_effect_rejected():
    with pytest.raises(ValueError):
        CapabilityDefinition(id="c", version="1", namespace={"authority": {"id": "a"}},
                             description="x", relationships=[{"type": "similar_to", "target": {"id": "t"}}])
    with pytest.raises(ValueError):
        CapabilityDefinition(id="c", version="1", namespace={"authority": {"id": "a"}},
                             description="x", effect={"class": "magical"})


def test_substitution_requires_explicit_policy():
    R = CapabilityRelationship
    # compatible_with / implements / anything: never auto-substitutable
    assert R.may_substitute("compatible_with") is False
    assert R.may_substitute("implements") is False
    # equivalent_to: only when policy accepts the asserting authority (CHP-CAP-016)
    assert R.may_substitute("equivalent_to") is False
    assert R.may_substitute("equivalent_to", policy_accepts_authority=True) is True
    # subtype_of: direction-sensitive AND policy (CHP-CAP-018)
    assert R.may_substitute("subtype_of", policy_accepts_authority=True) is False  # default direction
    assert R.may_substitute("subtype_of", direction="narrowing", policy_accepts_authority=True) is True
    # supersedes: no automatic migration (CHP-CAP-019)
    assert R.may_substitute("supersedes") is False
    assert R.may_substitute("supersedes", migration_policy=True) is True


def test_transitivity_and_similarity_are_not_equivalence():
    R = CapabilityRelationship
    assert R.is_transitive("compatible_with") is False   # CHP-CAP-017
    assert R.is_transitive("equivalent_to") is True
    assert R.is_transitive("subtype_of") is True
    assert R.is_symmetric("equivalent_to") is True
    assert R.is_symmetric("subtype_of") is False
    # similarity is NOT a relationship type — it can never grant substitution (CHP-CAP-009/015)
    assert R.may_substitute("similar", policy_accepts_authority=True) is False
