"""First-class EffectEvidence (proposal 0047, CHP-CORE-016).

Proves effect observation is distinct from executor completion: a completed execution may carry
an indeterminate/refuted/unobserved effect; only 'confirmed' confirms (never indeterminate,
CHP-CORE-014); observer provenance is preserved; a bad determination is rejected; and
reconciliation ADDS records without rewriting an earlier one (CHP-CORE-015).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import EffectEvidence

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/effect-evidence.schema.json").read_text()
)


def _effect(determination: str, **kw) -> EffectEvidence:
    base = dict(invocation_id="inv1", subject={"kind": "effect", "id": "orders_db@v2"},
                determination=determination, observer={"id": "urn:chp:observer:introspection"})
    base.update(kw)
    return EffectEvidence(**base)


def test_confirmed_effect_serializes_and_is_confirmed():
    e = _effect("confirmed", execution_id="exec1", observed_state={"rows": "3"})
    jsonschema.validate(e.to_dict(), _SCHEMA)
    assert e.is_confirmed() is True
    assert e.observer["id"] == "urn:chp:observer:introspection"  # provenance, not the executor


def test_non_confirmed_never_confirms():
    for d in ("indeterminate", "unobserved", "refuted"):
        e = _effect(d)
        assert e.is_confirmed() is False
        jsonschema.validate(e.to_dict(), _SCHEMA)


def test_effect_is_not_execution_completion():
    # CHP-CORE-016: an execution that COMPLETED can still have an unconfirmed effect. The type
    # carries no execution outcome/success field — determination is a separate truth.
    e = _effect("indeterminate")
    d = e.to_dict()
    assert not ({"outcome", "success"} & set(d))
    assert d["determination"] == "indeterminate"


def test_bad_determination_and_subject_rejected():
    with pytest.raises(ValueError):
        _effect("maybe")
    with pytest.raises(ValueError):
        EffectEvidence(invocation_id="i", subject={"kind": "effect"},  # no id
                       determination="confirmed", observer={"id": "o"})


def test_reconciliation_adds_record_without_rewriting():
    # CHP-CORE-015: a later observation is a NEW EffectEvidence; the earlier one is immutable.
    first = _effect("indeterminate", execution_id="exec1")
    later = _effect("confirmed", execution_id="exec1")
    assert first.determination == "indeterminate"   # unchanged by the later observation
    assert later.determination == "confirmed"
    assert first.id != later.id                      # distinct records for the same execution
    assert first.execution_id == later.execution_id
