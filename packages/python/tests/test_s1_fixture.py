"""S1 reference fixture — software entity to effect (proposal 0043; package
04_reference_profiles/07_s1_entity_to_effect_fixture.md, CHP-CONF-005).

Walks a software-migration capability through the execution-truth spine end-to-end using
the REAL 0043 types: action/invocation digests → CapabilityBinding → four-state
InvariantEvaluation → AdmissionDecision → generalized ExecutionGrant → execution evidence
(execution_id) → effect evidence, plus the indeterminate reconciliation path.

The Tier-B/C stages the package names (EntityRecord, Claim, VerificationResult,
ReadinessAssessment, CapabilityResolution) are not built yet; they are represented
minimally here (dicts) and marked, so this fixture grows into the full chain as those land.
It asserts the CHP-CORE invariants at each stage — this is the acceptance-gate demonstration.
"""

from __future__ import annotations

import asyncio
import tempfile

from chp_core import (
    AdmissionDecision,
    CapabilityBinding,
    CapabilityDescriptor,
    CorrelationContext,
    InvariantEvaluation,
    InvocationEnvelope,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from chp_core.digests import action_digest, invocation_digest
from chp_core.host import _stringify_floats
from chp_core.signing import build_approval_grant, generate_keypair, verify_approval_grant
from chp_core.store import _payload_commitment
from chp_core.types import DenialReason, ExecutionEvidence

# --- Stage 1-2: software entity + evidence (Tier-B stubs: dicts until the types land) ---
_ENTITY = {"id": "urn:chp:entity:migration-svc", "type": "service"}
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
