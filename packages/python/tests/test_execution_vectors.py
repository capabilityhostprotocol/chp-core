"""Execution-truth conformance vectors (proposal 0052; CHP-CONF-002/006).

The digests.json + provider-substitution.json vectors are the execution-truth conformance assets a
second implementation checks. Here the Python side re-verifies them as a CONSUMER (not the
generator), and — when node is present — shells the independent stdlib verifier (verify.mjs) to
prove cross-implementation agreement (CHP-IOP-001/002). Regeneration is guarded by
test_gen_vectors' git-diff check; this file guards the semantics.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from chp_core import digests, signing

VEC = Path(__file__).resolve().parents[3] / "spec" / "test-vectors"
_TS = "2026-01-01T00:00:00Z"


def _load(name):
    return json.loads((VEC / name).read_text())


def test_digests_vector_recomputes():
    v = _load("digests.json")
    ad = "sha256:" + __import__("hashlib").sha256(
        signing._canon_jcs(v["action_document"])).hexdigest()
    assert ad == v["action_digest"]  # action digest reproducible from the document
    assert digests.action_digest(
        capability=v["action_document"]["capability"],
        principal=v["action_document"]["principal"],
        action_input=v["action_document"]["input"],
    ) == v["action_digest"]
    # the invocation binds the action it carries
    assert v["invocation_document"]["action_digest"] == v["action_digest"]
    inv = "sha256:" + __import__("hashlib").sha256(
        signing._canon_jcs(v["invocation_document"])).hexdigest()
    assert inv == v["invocation_digest"]


def test_provider_substitution_invariants():
    v = _load("provider-substitution.json")
    a, b, g = v["invocation_a"], v["invocation_b"], v["grant_for_a"]
    # action_digest stable across providers; invocation_digest changed
    assert a["invocation_document"]["action_digest"] == v["action_digest"]
    assert b["invocation_document"]["action_digest"] == v["action_digest"]
    assert a["invocation_digest"] != b["invocation_digest"]
    # the grant is bound to A's attempt + A's executor
    assert signing.verify_approval_grant(g, at_time=_TS, expected_audience="prov-a").valid
    # a substituted provider (B) cannot wield A's grant → fresh admission required
    assert not signing.verify_approval_grant(g, at_time=_TS, expected_audience="prov-b").valid
    assert v["expected"] == {"action_digest_stable": True, "invocation_digest_changed": True,
                             "grant_valid_for_a": True, "grant_valid_for_b": False}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("vector", ["digests.json", "provider-substitution.json"])
def test_independent_verifier_agrees(vector):
    # Cross-impl (CHP-IOP): the stdlib JS verifier recomputes the digests and agrees.
    r = subprocess.run(["node", str(VEC / "verify.mjs"), str(VEC / vector)],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "VALID" in r.stdout, r.stdout + r.stderr
