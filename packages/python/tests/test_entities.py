"""Entity identity kernel — EntitySubject (proposal 0044, Tier B).

Proves the stable-id invariants: rotating display/identifiers/keys keeps the id (CHP-ENT-010);
only explicit succession creates a new entity that links back (CHP-ENT-001); external
identifiers are evidence-backed claims (CHP-ENT-002); kind grants nothing (CHP-ENT-003); status
is orthogonal and offboarding preserves the record (CHP-ENT-006/012); serializes under schema.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import Assertion, EntitySubject

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/entity-subject.schema.json").read_text()
)


def test_rotation_preserves_id_and_serializes():
    e = EntitySubject(id="urn:chp:entity:jane", kind="person", display={"name": "Jane"})
    jsonschema.validate(e.to_dict(), _SCHEMA)
    original_id = e.id
    # rotate the mutable, non-identifying surfaces: display + external identifiers
    e.display = {"name": "Jane Q. Smith"}
    e.identifiers = [{"kind": "email", "value": "jane@new.example", "assertion": "asrt_9"}]
    assert e.id == original_id  # CHP-ENT-010: continuity across rotation
    jsonschema.validate(e.to_dict(), _SCHEMA)


def test_external_identifiers_are_evidence_backed_claims():
    # CHP-ENT-002: an external identifier binding references the Assertion that backs it —
    # it is not canonical identity on its own.
    a = Assertion(claim_type="chp.identity.email",
                  issuer={"id": "urn:chp:verifier:mail"},
                  subject={"kind": "person", "id": "urn:chp:entity:jane"},
                  value="jane@example.com")
    e = EntitySubject(id="urn:chp:entity:jane", kind="person",
                      identifiers=[{"kind": "email", "value": "jane@example.com", "assertion": a.id}])
    jsonschema.validate(e.to_dict(), _SCHEMA)
    assert e.identifiers[0]["assertion"] == a.id  # binding cites its evidence


def test_kind_grants_nothing():
    # CHP-ENT-003: kind is informational. The kernel carries no capability/authority/trust field.
    e = EntitySubject(id="e1", kind="service")
    d = e.to_dict()
    assert not ({"capabilities", "authority", "trust", "qualified", "trusted"} & set(d))
    assert e.ref() == {"kind": "service", "id": "e1"}  # ref is identity only


def test_succession_creates_new_entity_linked_back():
    old = EntitySubject(id="urn:chp:entity:acme-inc", kind="organization", display={"name": "Acme"})
    new = old.succeed("urn:chp:entity:acme-llc", display={"name": "Acme LLC"})
    assert new.id != old.id                 # a NEW durable entity (CHP-ENT-001)
    assert new.succeeds_id == old.id        # linked back for continuity/verification
    assert old.id == "urn:chp:entity:acme-inc"  # predecessor unchanged
    jsonschema.validate(new.to_dict(), _SCHEMA)


def test_status_orthogonal_and_offboarding_preserves_record():
    e = EntitySubject(id="e1", kind="person", assertion_refs=["asrt_1"])
    e.status = "offboarded"
    d = e.to_dict()
    assert d["status"] == "offboarded"
    assert d["assertion_refs"] == ["asrt_1"]  # CHP-ENT-012: offboarding does not erase history
    jsonschema.validate(d, _SCHEMA)


def test_bad_status_rejected():
    with pytest.raises(ValueError):
        EntitySubject(id="e1", kind="person", status="deleted")
