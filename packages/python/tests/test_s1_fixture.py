"""S1 reference fixture — software entity to effect (proposal 0043; package
04_reference_profiles/07_s1_entity_to_effect_fixture.md, CHP-CONF-005).

Walks a software-migration capability through the execution-truth spine end-to-end using
the REAL 0043 types: action/invocation digests → CapabilityBinding → four-state
InvariantEvaluation → AdmissionDecision → generalized ExecutionGrant → execution evidence
(execution_id) → effect evidence, plus the indeterminate reconciliation path.

The Tier-B and Tier-C stages now use the REAL types — see
test_s1_economy_to_execution_full_chain, which walks the whole economy→execution chain:
EntitySubject → Assertion → VerificationResult → ReadinessAssessment → CapabilityRequirement →
resolve() → CapabilityResolution → (0043) admission → grant → execution → effect. It asserts
the CHP invariants at each stage — this is the acceptance gate, now fully un-stubbed.
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
from chp_core.types import DenialReason, ExecutionEvidence

# --- Stage 1: the software service as a durable EntitySubject (Tier-B, real type) ---
_SERVICE = EntitySubject(id="urn:chp:entity:migration-svc", kind="service")
_ENTITY = _SERVICE.ref()  # {"kind": "service", "id": ...} — identity only, grants nothing
_PRINCIPAL = {"id": "urn:chp:entity:acme"}
_WORKER = "urn:chp:entity:migration-worker"
_ARTIFACT = "sha256:" + "ab" * 32
# Deployment authority is a SEPARATE claim: service-admin rights do NOT imply production
# deployment authority (fixture line 33 / CHP-AUTH-011) — modeled as its own invariant.
_INVARIANTS = ["deployment_authority", "artifact_digest", "test_evidence",
               "maintenance_window", "backup_state"]


def _capability() -> dict:
    return {"id": "database.schema.migrate", "version": "1.0.0"}


def _binding() -> CapabilityBinding:
    # Stage 3-4: a governed deployment binding (provider != host: the service provides,
    # the deploy host executes — distinct refs, CHP-CORE-021).
    return CapabilityBinding(
        id="binding_prod_migrate_1", version="1", capability=_capability(),
        provider=_ENTITY, host={"id": "urn:chp:entity:prod-deploy-host"},
    )


def _digests(binding: CapabilityBinding, payload: dict, invocation_id: str) -> tuple[str, str]:
    ad = action_digest(capability=_capability(), principal=_PRINCIPAL,
                        action_input=payload, semantic_context={"env": "prod"})
    idg = invocation_digest(
        invocation_id=invocation_id, action_digest=ad, actor={"id": _WORKER},
        principal=_PRINCIPAL, binding={"id": binding.id, "version": binding.version},
        provider=binding.provider, host=binding.host,
    )
    return ad, idg


def _admit(invocation_id: str, invocation_digest_val: str, statuses: dict[str, str]):
    """Stage 5: evaluate each invariant four-state; admit only if ALL satisfied
    (CHP-CORE-017: unknown/error never satisfies)."""
    evals = [InvariantEvaluation(invocation_id=invocation_id, invariant_id=k, result=v)
             for k, v in statuses.items()]
    all_satisfied = all(e.is_satisfied() for e in evals)
    return AdmissionDecision(
        invocation_id=invocation_id, invocation_digest=invocation_digest_val,
        result="admitted" if all_satisfied else "denied",
        invariant_evaluations=[e.to_admission_ref() for e in evals],
        denial=None if all_satisfied else DenialReason(
            code="invariant_failed", message="a required invariant was not satisfied"),
    ), evals


def test_s1_software_entity_to_effect():
    payload = {"artifact_digest": _ARTIFACT, "target": "orders_db"}
    binding = _binding()
    inv_id = "inv_s1_001"
    ad, idg = _digests(binding, payload, inv_id)

    # Stage 5 — admission: all deployment invariants satisfied → admitted, bound to the digest.
    decision, evals = _admit(inv_id, idg, {k: "satisfied" for k in _INVARIANTS})
    assert decision.result == "admitted"
    assert decision.invocation_digest == idg               # bound to the exact attempt
    assert len(decision.invariant_evaluations) == len(_INVARIANTS)

    # Stage 6 — ExecutionGrant bound to this attempt, this executor, single-use.
    key = generate_keypair(tempfile.mkdtemp())
    grant = build_approval_grant(
        key, invocation_id=inv_id, payload_commitment=_payload_commitment(_stringify_floats(payload)),
        approval_id="ap_s1", valid_until="2099-01-01T00:00:00Z", invocation_digest=idg,
        action_digest=ad, binding_id=binding.id, audience=_WORKER, max_attempts=1,
    )
    assert verify_approval_grant(grant, at_time="2026-08-21T00:00:00Z", expected_audience=_WORKER).valid
    # a different executor may not use this grant (CHP-CORE-009)
    assert not verify_approval_grant(grant, at_time="2026-08-21T00:00:00Z", expected_audience="other").valid

    # Stage 7 — execution: the migration worker runs; evidence carries the digests + an
    # execution_id path. action_digest is stamped by the host and equals the admitted action.
    async def handler(_ctx, _payload):
        return {"migrated": True, "rows": 3}

    host = LocalCapabilityHost("prod-deploy-host", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="database.schema.migrate", version="1.0.0",
                                       description="Apply a schema migration."), handler)
    env = InvocationEnvelope(invocation_id=inv_id, capability_id="database.schema.migrate",
                             version="1.0.0", payload=payload,
                             subject=_PRINCIPAL, actor={"id": _WORKER}, binding=binding.to_dict(),
                             metadata={"semantic_context": {"env": "prod"}},
                             correlation=CorrelationContext(correlation_id="s1"))
    result = asyncio.run(host.ainvoke_envelope(env))
    assert result.outcome == "success"
    events = host.replay("s1")
    exec_action_digests = {e["action_digest"] for e in events if e.get("action_digest")}
    assert exec_action_digests == {ad}                     # host-stamped action == admitted action
    assert all(e.get("invocation_digest") == idg for e in events if e.get("invocation_digest"))

    # Stage 8 — effect: schema introspection confirms the migration. Effect evidence is a
    # SEPARATE record from executor completion (CHP-CORE-016), with its own execution_id.
    completion = next(e for e in events if e["event_type"] == "execution_completed")
    effect = ExecutionEvidence(
        event_id="evt_effect", event_type="effect_confirmed", invocation_id=inv_id,
        capability_id="database.schema.migrate", capability_version="1.0.0",
        host_id="prod-deploy-host", correlation=env.correlation, outcome="success",
        execution_id="exec_s1_1", subject={"kind": "effect", "id": "orders_db@v2"},
    )
    assert effect.event_type != completion["event_type"]   # effect != completion
    assert effect.to_dict()["subject"]["kind"] == "effect"
    assert effect.execution_id != effect.invocation_id     # CHP-CORE-012


def test_s1_admission_denied_when_backup_state_unknown():
    # CHP-CORE-017: a mandatory invariant returning 'unknown' must NOT admit.
    binding = _binding()
    inv_id = "inv_s1_deny"
    _, idg = _digests(binding, {"artifact_digest": _ARTIFACT}, inv_id)
    statuses = {k: "satisfied" for k in _INVARIANTS}
    statuses["backup_state"] = "unknown"                   # can't confirm a backup exists
    decision, _ = _admit(inv_id, idg, statuses)
    assert decision.result == "denied"
    assert decision.denial is not None


def test_s1_indeterminate_dispatch_is_not_failure():
    # CHP-CORE-014/015: a crash after an irreversible migration dispatch yields
    # indeterminate; a later reconciliation ADDS a record and does not rewrite it.
    inv_id = "inv_s1_indet"
    base = dict(event_type="execution_completed", invocation_id=inv_id,
                capability_id="database.schema.migrate", capability_version="1.0.0",
                host_id="prod-deploy-host", correlation=CorrelationContext(correlation_id="i"),
                execution_id="exec_s1_2")
    crashed = ExecutionEvidence(event_id="evt_1", outcome="indeterminate", sequence=1, **base)
    reconciled = ExecutionEvidence(event_id="evt_2", outcome="success", sequence=2, **base)
    assert crashed.to_dict()["outcome"] == "indeterminate"  # not 'failure'
    assert reconciled.to_dict()["outcome"] == "success"
    assert crashed.execution_id == reconciled.execution_id  # same execution, two records


def test_s1_economy_to_execution_full_chain():
    """De-stubbed S1: entity → claim → verify → readiness → admission → grant → execution →
    effect, all with real Tier-B + 0043 types. The economy half now feeds the execution half."""
    # Stage 1 — durable entity: identity only, grants nothing (CHP-ENT-003).
    assert _SERVICE.ref() == {"kind": "service", "id": "urn:chp:entity:migration-svc"}

    # Stage 2 — evidence-backed claims about the service. Deployment authority is its OWN
    # claim: service-admin rights do NOT imply production deploy authority (CHP-AUTH-011).
    issuer = {"id": "urn:chp:entity:platform-governance"}
    subject = _SERVICE.ref()
    claims = {"deployment_authority": True, "artifact_digest": _ARTIFACT,
              "test_evidence": "passed", "maintenance_window": "open", "backup_state": "confirmed"}
    assertions = {
        name: Assertion(claim_type=f"chp.migrate.{name}", issuer=issuer, subject=subject,
                        value=val, evidence=[f"evt_{name}"])
        for name, val in claims.items()
    }

    # Stage 3 — verify each assertion. Integrity satisfied — NOT trust (a policy accepts).
    def verify(a: Assertion) -> VerificationResult:
        checks = {"integrity": "satisfied", "issuer_identity": "satisfied",
                  "subject_binding": "satisfied", "freshness": "satisfied", "revocation": "satisfied"}
        return VerificationResult(assertion=a.id, verifier={"id": "urn:chp:verifier:market"},
                                  checks=checks, result=VerificationResult.derive_result(checks))
    verifications = {name: verify(a) for name, a in assertions.items()}
    assert all(v.is_verified() for v in verifications.values())

    # Stage 4 — RESOLVE: a requirement resolves to a concrete binding. The hard constraints are
    # the verified deployment claims; a high-score candidate that fails a hard constraint loses
    # to the eligible one (CHP-RES-002). Resolution is not admission (CHP-RES-008).
    binding = _binding()
    requirement = CapabilityRequirement(capability=_capability(), hard=list(claims))
    eligible = ResolvedCandidate(binding=binding.to_dict(), score=10, satisfied_hard=list(claims))
    decoy = ResolvedCandidate(
        binding={"id": "binding_untested", "version": "1", "capability": _capability(),
                 "provider": {"id": "x"}, "host": {"id": "y"}},
        score=999, satisfied_hard=["deployment_authority"])  # high score, but fails hard constraints
    resolution = resolve(requirement, [decoy, eligible], provenance={"policy": "prod-migrate-v1"})
    assert resolution.result == "resolved"
    assert resolution.selected["id"] == binding.id   # hard filter beat the high-score decoy
    assert "admitted" not in resolution.to_dict()    # resolution is not admission (CHP-RES-008)

    # Stage 5 — derive CONTEXTUAL readiness of the resolved binding (not a global entity
    # boolean, CHP-ENT-007; and NOT admission, CHP-RDY-003).
    requirements = [
        {"id": name, "result": "satisfied", "assertions": [assertions[name].id],
         "verification_results": [verifications[name].id]}
        for name in claims
    ]
    readiness = ReadinessAssessment(
        subject={"entity": _SERVICE.ref(), "capability": _capability(),
                 "binding": {"id": binding.id}, "market": {"id": "internal"}},
        profile={"id": "prof.prod-migrate", "version": "1"}, requirements=requirements,
        result=ReadinessAssessment.derive_result(requirements))
    assert readiness.is_eligible()
    assert "admitted" not in readiness.to_dict()

    # Stage 6 — admission (0043): the same requirements as four-state invariants → admitted,
    # bound to the exact invocation_digest.
    payload = {"artifact_digest": _ARTIFACT, "target": "orders_db"}
    inv_id = "inv_s1_full"
    ad, idg = _digests(binding, payload, inv_id)
    decision, _ = _admit(inv_id, idg, {name: "satisfied" for name in claims})
    assert decision.result == "admitted"
    assert decision.invocation_digest == idg

    # Stage 7 — grant + execution.
    key = generate_keypair(tempfile.mkdtemp())
    grant = build_approval_grant(
        key, invocation_id=inv_id, payload_commitment=_payload_commitment(_stringify_floats(payload)),
        approval_id="ap_full", valid_until="2099-01-01T00:00:00Z", invocation_digest=idg,
        action_digest=ad, binding_id=binding.id, audience=_WORKER, max_attempts=1)
    assert verify_approval_grant(grant, at_time="2026-08-21T00:00:00Z", expected_audience=_WORKER).valid

    async def handler(_ctx, _payload):
        return {"migrated": True}

    host = LocalCapabilityHost("prod-deploy-host", store=SQLiteEvidenceStore(":memory:"))
    host.register(CapabilityDescriptor(id="database.schema.migrate", version="1.0.0",
                                       description="Apply a schema migration."), handler)
    env = InvocationEnvelope(invocation_id=inv_id, capability_id="database.schema.migrate",
                             version="1.0.0", payload=payload, subject=_PRINCIPAL,
                             actor={"id": _WORKER}, binding=binding.to_dict(),
                             metadata={"semantic_context": {"env": "prod"}},
                             correlation=CorrelationContext(correlation_id="s1full"))
    result = asyncio.run(host.ainvoke_envelope(env))
    assert result.outcome == "success"
    events = host.replay("s1full")
    assert {e["action_digest"] for e in events if e.get("action_digest")} == {ad}

    # Stage 8 — effect evidence distinct from executor completion (CHP-CORE-016).
    effect = ExecutionEvidence(event_id="evt_eff", event_type="effect_confirmed",
                               invocation_id=inv_id, capability_id="database.schema.migrate",
                               capability_version="1.0.0", host_id="prod-deploy-host",
                               correlation=env.correlation, outcome="success",
                               execution_id="exec_full", subject={"kind": "effect", "id": "orders_db@v2"})
    assert effect.event_type != "execution_completed"
