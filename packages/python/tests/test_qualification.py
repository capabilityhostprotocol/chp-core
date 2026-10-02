"""Verdict-free QualificationClaim (proposal 0050, CHP-SUP-013)."""
from __future__ import annotations

import unittest

from chp_core import QualificationClaim, observation
from chp_core.qualification import QualificationClaim as QC, observation as obs


class ObservationTests(unittest.TestCase):
    def test_self_asserted_needs_no_evidence(self):
        o = obs("contract_shape", "matches", "self_asserted")
        self.assertEqual(o["provenance"], "self_asserted")
        self.assertNotIn("evidence", o)

    def test_inferred_needs_no_evidence(self):
        o = obs("likely_json_tool", True, "inferred")
        self.assertEqual(o["value"], True)

    def test_externally_verified_requires_evidence(self):
        with self.assertRaises(ValueError):
            obs("contract_conformance", "pass", "externally_verified")          # no evidence
        o = obs("contract_conformance", "pass", "externally_verified", evidence=["assrt_1"])
        self.assertEqual(o["evidence"], ["assrt_1"])

    def test_execution_derived_requires_evidence(self):
        with self.assertRaises(ValueError):
            obs("latency_p95_ms", 42, "execution_derived")                      # no evidence
        self.assertTrue(obs("latency_p95_ms", 42, "execution_derived", evidence=["eff_9"]))

    def test_unknown_provenance_rejected(self):
        with self.assertRaises(ValueError):
            obs("x", 1, "rumoured")

    def test_conclusion_property_rejected(self):
        for bad in ("qualified", "authorized", "approved", "trusted", "admitted"):
            with self.assertRaises(ValueError):
                obs(bad, True, "self_asserted")


class QualificationClaimTests(unittest.TestCase):
    def _valid(self) -> QualificationClaim:
        return QualificationClaim(
            subject="data.json.object.create",
            purpose="serve JSON-object creation in the catalog",
            assessor="entity_assessor_1",
            observations=[
                obs("contract_conformance", "pass", "externally_verified", evidence=["assrt_1"]),
                obs("interpreted_from_readme", True, "inferred"),
            ],
        )

    def test_valid_claim_has_no_verdict(self):
        c = self._valid()
        blob = c.to_json()
        for forbidden in ("qualified", "authorized", "approved", "trusted", "admitted", "verdict"):
            self.assertNotIn(forbidden, blob)
        self.assertEqual(blob["subject"], "data.json.object.create")
        self.assertTrue(blob["claim_id"].startswith("qc_"))
        self.assertTrue(blob["created_at"])

    def test_purpose_is_required(self):
        with self.assertRaises(ValueError):
            QualificationClaim(subject="s", purpose="", assessor="a")

    def test_subject_and_assessor_required(self):
        with self.assertRaises(ValueError):
            QualificationClaim(subject="", purpose="p", assessor="a")
        with self.assertRaises(ValueError):
            QualificationClaim(subject="s", purpose="p", assessor="")

    def test_rejects_forbidden_conclusion_smuggled_in_a_value(self):
        # A conclusion hidden inside an observation value must still be refused (verdict-free by
        # construction, not convention).
        with self.assertRaises(ValueError):
            QualificationClaim(
                subject="s", purpose="p", assessor="a",
                observations=[obs("report", {"approved": True}, "self_asserted")],
            )

    def test_observation_evidence_discipline_enforced_on_construct(self):
        with self.assertRaises(ValueError):
            QualificationClaim(
                subject="s", purpose="p", assessor="a",
                observations=[{"property": "x", "value": 1, "provenance": "execution_derived"}],
            )

    def test_cited_evidence_aggregates(self):
        c = QualificationClaim(
            subject="s", purpose="p", assessor="a",
            observations=[
                obs("a", 1, "externally_verified", evidence=["e1", "e2"]),
                obs("b", 2, "execution_derived", evidence=["e3"]),
                obs("c", 3, "self_asserted"),
            ],
        )
        self.assertEqual(c.cited_evidence(), ["e1", "e2", "e3"])

    def test_exported_from_package_root(self):
        self.assertIs(QC, QualificationClaim)
        self.assertEqual(obs, observation)


if __name__ == "__main__":
    unittest.main()
