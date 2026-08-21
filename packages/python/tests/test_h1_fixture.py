"""H1 reference fixture — licensed professional entity to effect (proposal 0046; package
04_reference_profiles/05_h1_entity_to_effect_fixture.md, CHP-CONF-003).

A licensed lawyer performs a governed legal-document review. Walks the SAME full chain as S1
with the real types — entity → claim → verify → readiness → requirement → resolve → admission →
grant → execution → effect — proving one architecture spans the human profile too.

Distinct H1 invariant: professional capacity is the professional's OWN, issued by the licensing
authority, NOT delegated from the requester (CHP-AUTH-010) — the fixture asserts the licence
issuer is the bar, not the client.
"""

from __future__ import annotations

import asyncio
import tempfile

from chp_core import (
    AdmissionDecision,
    Assertion,
    CapabilityBinding,
    CapabilityDescriptor,
    CapabilityRequirement,
    CorrelationContext,
    EntitySubject,
    InvariantEvaluation,
    InvocationEnvelope,
    LocalCapabilityHost,
    ReadinessAssessment,
    ResolvedCandidate,
    SQLiteEvidenceStore,
    VerificationResult,
    resolve,
)
from chp_core.digests import action_digest, invocation_digest
from chp_core.host import _stringify_floats
from chp_core.signing import build_approval_grant, generate_keypair, verify_approval_grant
from chp_core.store import _payload_commitment
from chp_core.types import ExecutionEvidence

_LAWYER = EntitySubject(id="urn:chp:entity:jane-lawyer", kind="person")
_CLIENT = {"id": "urn:chp:entity:acme"}                 # the requester/principal
_BAR = {"id": "urn:chp:authority:law-society-ontario"}   # the licensing authority (issuer)
_CAP = {"id": "legal.document.review", "version": "1.0.0"}
_ARTIFACT = "sha256:" + "cd" * 32
# Professional qualifications — the licence is the lawyer's OWN (issued by the bar), the
# conflict-clear is matter-specific. Requester admin rights confer none of these.
_QUALS = {"bar_licence": "active", "jurisdiction_admission": "CA-ON", "conflict_clear": True}


def _binding() -> CapabilityBinding:
    return CapabilityBinding(id="binding_jane_review_1", version="1", capability=_CAP,
                             provider=_LAWYER.ref(), host={"id": "urn:chp:entity:legal-network"})


def _digests(binding: CapabilityBinding, payload: dict, inv_id: str) -> tuple[str, str]:
    ad = action_digest(capability=_CAP, principal=_CLIENT, action_input=payload,
                        semantic_context={"jurisdiction": "CA-ON"})
    idg = invocation_digest(invocation_id=inv_id, action_digest=ad, actor=_LAWYER.ref(),
                            principal=_CLIENT, binding={"id": binding.id, "version": binding.version},
                            provider=binding.provider, host=binding.host)
    return ad, idg


def test_h1_licensed_professional_to_effect():
    # Stage 1-2 — the lawyer entity + professional claims issued by the BAR, not the client.
    subject = _LAWYER.ref()
    assertions = {name: Assertion(claim_type=f"chp.legal.{name}", issuer=_BAR, subject=subject,
                                  value=val, evidence=[f"evt_{name}"])
                  for name, val in _QUALS.items()}
    # CHP-AUTH-010: professional capacity is not delegated from the requester.
    assert all(a.issuer == _BAR and a.issuer != _CLIENT for a in assertions.values())

    # Stage 3 — verify each qualification (integrity satisfied; not trust).
    def verify(a: Assertion) -> VerificationResult:
        checks = {"integrity": "satisfied", "issuer_identity": "satisfied",
                  "subject_binding": "satisfied", "freshness": "satisfied", "revocation": "satisfied"}
        return VerificationResult(assertion=a.id, verifier={"id": "urn:chp:verifier:legal-market"},
                                  checks=checks, result=VerificationResult.derive_result(checks))
    verifications = {name: verify(a) for name, a in assertions.items()}
    assert all(v.is_verified() for v in verifications.values())

    # Stage 4 — resolve a review requirement to the lawyer's binding (hard filter).
    binding = _binding()
    requirement = CapabilityRequirement(capability=_CAP, hard=list(_QUALS))
    eligible = ResolvedCandidate(binding=binding.to_dict(), score=10, satisfied_hard=list(_QUALS))
    unlicensed = ResolvedCandidate(binding={"id": "binding_paralegal", "version": "1",
                                            "capability": _CAP, "provider": {"id": "p"}, "host": {"id": "h"}},
                                   score=500, satisfied_hard=["conflict_clear"])  # no bar_licence
    resolution = resolve(requirement, [unlicensed, eligible], provenance={"policy": "legal-review-v1"})
    assert resolution.result == "resolved"
    assert resolution.selected["id"] == binding.id   # the unlicensed high-score candidate is filtered

    # Stage 5 — contextual readiness (derived; not admission).
    requirements = [{"id": n, "result": "satisfied", "assertions": [assertions[n].id],
                     "verification_results": [verifications[n].id]} for n in _QUALS]
    readiness = ReadinessAssessment(
        subject={"entity": subject, "capability": _CAP, "binding": {"id": binding.id},
                 "market": {"id": "legal"}},
        profile={"id": "prof.legal-review", "version": "1"}, requirements=requirements,
        result=ReadinessAssessment.derive_result(requirements))
    assert readiness.is_eligible()
    assert "admitted" not in readiness.to_dict()

    # Stage 6 — admission bound to the invocation_digest.
    payload = {"artifact_digest": _ARTIFACT, "matter": "acme-merger"}
    inv_id = "inv_h1_001"
    ad, idg = _digests(binding, payload, inv_id)
    evals = [InvariantEvaluation(invocation_id=inv_id, invariant_id=n, result="satisfied") for n in _QUALS]
    decision = AdmissionDecision(invocation_id=inv_id, invocation_digest=idg, result="admitted",
                                 invariant_evaluations=[e.to_admission_ref() for e in evals])
    assert decision.result == "admitted"
    assert decision.invocation_digest == idg

    # Stage 7 — grant + execution (the review produces an attestation).
    key = generate_keypair(tempfile.mkdtemp())
    grant = build_approval_grant(
        key, invocation_id=inv_id, payload_commitment=_payload_commitment(_stringify_floats(payload)),
        approval_id="ap_h1", valid_until="2099-01-01T00:00:00Z", invocation_digest=idg,
        action_digest=ad, binding_id=binding.id, audience=_LAWYER.id, max_attempts=1)
    assert verify_approval_grant(grant, at_time="2026-08-21T00:00:00Z", expected_audience=_LAWYER.id).valid

    async def handler(_ctx, _payload):
        return {"reviewed": True, "opinion": "no blocking issues"}

    host = LocalCapabilityHost("legal-network", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="legal.document.review", version="1.0.0",
                                       description="Licensed review of a legal document."), handler)
    env = InvocationEnvelope(invocation_id=inv_id, capability_id="legal.document.review",
                             version="1.0.0", payload=payload, subject=_CLIENT,
                             actor=_LAWYER.ref(), binding=binding.to_dict(),
                             metadata={"semantic_context": {"jurisdiction": "CA-ON"}},
                             correlation=CorrelationContext(correlation_id="h1"))
    result = asyncio.run(host.ainvoke_envelope(env))
    assert result.outcome == "success"
    events = host.replay("h1")
    assert {e["action_digest"] for e in events if e.get("action_digest")} == {ad}

    # Stage 8 — effect (the signed opinion) distinct from executor completion (CHP-CORE-016).
    effect = ExecutionEvidence(event_id="evt_opinion", event_type="effect_confirmed",
                               invocation_id=inv_id, capability_id="legal.document.review",
                               capability_version="1.0.0", host_id="legal-network",
                               correlation=env.correlation, outcome="success",
                               execution_id="exec_h1", subject={"kind": "effect", "id": "opinion:acme-merger"})
    assert effect.event_type != "execution_completed"
    assert effect.to_dict()["subject"]["kind"] == "effect"
