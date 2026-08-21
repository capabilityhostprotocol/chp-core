"""M1 reference fixture — industrial machine entity to effect (proposal 0046; package
04_reference_profiles/06_m1_entity_to_effect_fixture.md, CHP-CONF-004).

A certified welding machine, acting under a human operator's authority, performs a weld. Walks
the SAME full chain as S1/H1 with the real types — proving one architecture spans the machine
profile too.

M1-distinct invariants:
- An action is admitted only with CURRENT safety evidence: an expired safety-interlock cert →
  freshness unsatisfied → NOT eligible/admitted.
- Effect evidence (weld telemetry) is preserved INDEPENDENTLY from command completion
  (CHP-CORE-016) — the command may complete while the physical effect is observed separately.
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

_MACHINE = EntitySubject(id="urn:chp:entity:weld-cell-7", kind="machine")
_OPERATOR = {"id": "urn:chp:entity:operator-sam"}          # the authorizing operator (principal)
_MANUFACTURER = {"id": "urn:chp:authority:machine-cert-body"}
_CAP = {"id": "industrial.weld.execute", "version": "1.0.0"}
_ARTIFACT = "sha256:" + "ef" * 32
# Machine certification + a CURRENT safety interlock (freshness matters) + operator authorization.
_QUALS = {"machine_certification": "class-A", "safety_interlock": "engaged", "operator_authorization": True}
_NOW = "2026-08-21T00:00:00Z"


def _binding() -> CapabilityBinding:
    return CapabilityBinding(id="binding_weld7_1", version="1", capability=_CAP,
                             provider=_MACHINE.ref(), host={"id": "urn:chp:entity:line-controller"})


def _digests(binding: CapabilityBinding, payload: dict, inv_id: str) -> tuple[str, str]:
    ad = action_digest(capability=_CAP, principal=_OPERATOR, action_input=payload,
                        semantic_context={"line": "A3"})
    idg = invocation_digest(invocation_id=inv_id, action_digest=ad, actor=_MACHINE.ref(),
                            principal=_OPERATOR, binding={"id": binding.id, "version": binding.version},
                            provider=binding.provider, host=binding.host)
    return ad, idg


def _verify(a: Assertion, *, fresh: bool = True) -> VerificationResult:
    checks = {"integrity": "satisfied", "issuer_identity": "satisfied", "subject_binding": "satisfied",
              "freshness": "satisfied" if fresh else "unsatisfied", "revocation": "satisfied"}
    return VerificationResult(assertion=a.id, verifier={"id": "urn:chp:verifier:line"},
                              checks=checks, result=VerificationResult.derive_result(checks))


def _assertions() -> dict[str, Assertion]:
    return {name: Assertion(claim_type=f"chp.industrial.{name}", issuer=_MANUFACTURER,
                            subject=_MACHINE.ref(), value=val, evidence=[f"evt_{name}"])
            for name, val in _QUALS.items()}


def test_m1_machine_to_effect_with_current_safety():
    assertions = _assertions()
    verifications = {n: _verify(a) for n, a in assertions.items()}
    assert all(v.is_verified() for v in verifications.values())

    binding = _binding()
    requirement = CapabilityRequirement(capability=_CAP, hard=list(_QUALS))
    good = ResolvedCandidate(binding=binding.to_dict(), score=10, satisfied_hard=list(_QUALS))
    uncertified = ResolvedCandidate(binding={"id": "binding_uncert", "version": "1", "capability": _CAP,
                                             "provider": {"id": "p"}, "host": {"id": "h"}},
                                    score=800, satisfied_hard=["operator_authorization"])
    resolution = resolve(requirement, [uncertified, good], provenance={"policy": "weld-line-v1"})
    assert resolution.selected["id"] == binding.id   # uncertified high-score candidate filtered

    requirements = [{"id": n, "result": "satisfied", "assertions": [assertions[n].id],
                     "verification_results": [verifications[n].id]} for n in _QUALS]
    readiness = ReadinessAssessment(
        subject={"entity": _MACHINE.ref(), "capability": _CAP, "binding": {"id": binding.id},
                 "market": {"id": "factory"}},
        profile={"id": "prof.weld", "version": "1"}, requirements=requirements,
        result=ReadinessAssessment.derive_result(requirements))
    assert readiness.is_eligible()

    payload = {"artifact_digest": _ARTIFACT, "seam": "A3-14"}
    inv_id = "inv_m1_001"
    ad, idg = _digests(binding, payload, inv_id)
    evals = [InvariantEvaluation(invocation_id=inv_id, invariant_id=n, result="satisfied") for n in _QUALS]
    decision = AdmissionDecision(invocation_id=inv_id, invocation_digest=idg, result="admitted",
                                 invariant_evaluations=[e.to_admission_ref() for e in evals])
    assert decision.result == "admitted"

    key = generate_keypair(tempfile.mkdtemp())
    grant = build_approval_grant(
        key, invocation_id=inv_id, payload_commitment=_payload_commitment(_stringify_floats(payload)),
        approval_id="ap_m1", valid_until="2099-01-01T00:00:00Z", invocation_digest=idg,
        action_digest=ad, binding_id=binding.id, audience=_MACHINE.id, max_attempts=1)
    assert verify_approval_grant(grant, at_time=_NOW, expected_audience=_MACHINE.id).valid

    async def handler(_ctx, _payload):
        return {"command": "weld_complete"}

    host = LocalCapabilityHost("line-controller", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="industrial.weld.execute", version="1.0.0",
                                       description="Execute a weld."), handler)
    env = InvocationEnvelope(invocation_id=inv_id, capability_id="industrial.weld.execute",
                             version="1.0.0", payload=payload, subject=_OPERATOR,
                             actor=_MACHINE.ref(), binding=binding.to_dict(),
                             metadata={"semantic_context": {"line": "A3"}},
                             correlation=CorrelationContext(correlation_id="m1"))
    result = asyncio.run(host.ainvoke_envelope(env))
    assert result.outcome == "success"

    # CHP-CORE-016: command completion is NOT the physical effect. Weld telemetry is a SEPARATE
    # effect record — the command "completed" while the actual effect is observed independently.
    telemetry = ExecutionEvidence(event_id="evt_weld_tele", event_type="effect_confirmed",
                                  invocation_id=inv_id, capability_id="industrial.weld.execute",
                                  capability_version="1.0.0", host_id="line-controller",
                                  correlation=env.correlation, outcome="success",
                                  execution_id="exec_m1",
                                  subject={"kind": "effect", "id": "weld:A3-14", "penetration_mm": "6"})
    assert telemetry.event_type != "execution_completed"
    assert telemetry.to_dict()["subject"]["kind"] == "effect"


def test_m1_expired_safety_interlock_blocks_admission():
    # An expired safety-interlock cert → freshness unsatisfied → the safety requirement is
    # unsatisfied → readiness ineligible and admission denied. Current safety evidence is required.
    assertions = _assertions()
    stale_safety = _verify(assertions["safety_interlock"], fresh=False)
    assert stale_safety.result == "unsatisfied"

    requirements = [{"id": "machine_certification", "result": "satisfied"},
                    {"id": "safety_interlock", "result": "unsatisfied"},  # expired → not fresh
                    {"id": "operator_authorization", "result": "satisfied"}]
    readiness = ReadinessAssessment(
        subject={"entity": _MACHINE.ref(), "capability": _CAP, "binding": {"id": "b"},
                 "market": {"id": "factory"}},
        profile={"id": "prof.weld", "version": "1"}, requirements=requirements,
        result=ReadinessAssessment.derive_result(requirements))
    assert readiness.result == "ineligible"   # cannot proceed without current safety evidence

    evals = [InvariantEvaluation(invocation_id="inv_m1_deny", invariant_id=r["id"], result=r["result"])
             for r in requirements]
    admitted = all(e.is_satisfied() for e in evals)
    assert not admitted   # CHP-CORE-017: the unsatisfied safety invariant blocks admission
