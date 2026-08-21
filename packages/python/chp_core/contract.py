"""Contract validation + functional fit (proposal 0051, Tier C runtime enforcement).

CapabilityDefinition declares input/output/effect CONTRACTS (proposal 0045); this module
ENFORCES them at runtime and computes whether one capability functionally fits another.

Every check is four-state — satisfied / unsatisfied / unknown / error — the same vocabulary as
InvariantEvaluation, and the same rule: **only 'satisfied' satisfies**. A missing schema, or a
default install without the optional ``jsonschema`` validator, yields ``unknown`` — never a silent
pass (that would turn a trust-boundary check off). This is the discipline CHP-CAP-004/005/006 and
CHP-RES-003/011 require: an undetermined contract is undetermined, not accepted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .capability_definition import CapabilityDefinition
from .host import jsonschema_module
from .types import JSON, new_id, utc_now

SATISFIED, UNSATISFIED, UNKNOWN, ERROR = "satisfied", "unsatisfied", "unknown", "error"
STATES = frozenset({SATISFIED, UNSATISFIED, UNKNOWN, ERROR})


def _validate_against(schema: JSON | None, value: JSON) -> str:
    """Four-state validation of ``value`` against a JSON Schema. No schema declared → unknown
    (the contract cannot be judged, never silently satisfied). jsonschema not installed → unknown
    (announced degradation, chp-core is dependency-free). Valid → satisfied; invalid → unsatisfied;
    a malformed schema → error."""
    if schema is None:
        return UNKNOWN
    js = jsonschema_module()
    if js is None:
        return UNKNOWN
    try:
        js.validate(value, schema)
    except js.ValidationError:
        return UNSATISFIED
    except Exception:  # malformed schema, etc. — an error is not a pass
        return ERROR
    return SATISFIED


def validate_input(definition: CapabilityDefinition, value: JSON) -> str:
    """CHP-CAP-004 — validate an invocation's input against the definition's input contract."""
    return _validate_against(definition.input_schema, value)


def validate_output(definition: CapabilityDefinition, value: JSON) -> str:
    """CHP-CAP-005 — validate a result against the definition's output contract."""
    return _validate_against(definition.output_schema, value)


def check_effect(definition: CapabilityDefinition, claimed_class: str | None) -> str:
    """CHP-CAP-006 — a capability may not claim an effect it did not declare. The definition's
    declared effect class must equal the claimed class. Undeclared or unclaimed → unknown (cannot
    judge, never silently satisfied); an unrecognised claimed class → error; a mismatch →
    unsatisfied; equal → satisfied."""
    declared = definition.effect.get("class") if isinstance(definition.effect, dict) else None
    if declared is None or claimed_class is None:
        return UNKNOWN
    if claimed_class not in CapabilityDefinition.EFFECT_CLASSES:
        return ERROR
    return SATISFIED if claimed_class == declared else UNSATISFIED


def functional_fit(required: CapabilityDefinition, candidate: CapabilityDefinition) -> str:
    """CHP-RES-003 / CHP-RES-011 — does ``candidate`` functionally satisfy ``required``?

    Computed, not asserted. A different capability id with no declared substitutable relationship
    does not fit (unsatisfied). A declared effect-class mismatch does not fit (unsatisfied). When
    the information needed to judge is absent — no declared effect on either side — fit is
    UNKNOWN and unknown is PRESERVED (CHP-RES-011): a resolver must not promote it to eligible.
    Same id + compatible declared effect → satisfied.

    Note: a declared relationship ALONE never authorises substitution (CHP-CAP-015); a candidate
    with a different id but a declared substitutable relationship is left UNKNOWN here for an
    explicit resolver policy to accept — never silently satisfied."""
    same_id = candidate.id == required.id
    rel_targets = {r.get("target", {}).get("id") for r in candidate.relationships}
    if not same_id and required.id not in rel_targets:
        return UNSATISFIED  # unrelated capability — cannot fit
    req_effect = required.effect.get("class") if isinstance(required.effect, dict) else None
    cand_effect = candidate.effect.get("class") if isinstance(candidate.effect, dict) else None
    if req_effect is not None and cand_effect is not None and req_effect != cand_effect:
        return UNSATISFIED  # declared effect mismatch
    if not same_id:
        return UNKNOWN  # related-but-not-same → needs explicit policy (CHP-CAP-015)
    if req_effect is None or cand_effect is None:
        return UNKNOWN  # cannot judge fit without both effects declared — preserve unknown
    return SATISFIED


def evidence_fit(required_evidence: list[str], contract: object | None) -> str:
    """CHP-RES-005 — does a candidate's EvidenceContract satisfy a requirement's evidence needs?

    ``required_evidence`` is the evidence kinds the requirement needs execution to produce;
    ``contract`` is the candidate's EvidenceContract (declaring ``execution_produces``) or None.
    Four-state, unknown-preserving: no evidence required → satisfied (nothing to meet); a contract
    that promises every required kind → satisfied; one missing any → unsatisfied; no contract when
    evidence IS required → UNKNOWN (cannot judge — never silently satisfied, CHP-RES-011).

    Note the contract is a PROMISE, not evidence (EvidenceContract ≠ Evidence): a satisfied
    evidence-fit means the candidate is ELIGIBLE to be resolved, not that the evidence exists —
    Core still evaluates the actual evidence at execution."""
    if not required_evidence:
        return SATISFIED
    if contract is None:
        return UNKNOWN
    produces = set(getattr(contract, "execution_produces", None)
                   or (contract.get("execution_produces", []) if isinstance(contract, dict) else []))
    return SATISFIED if set(required_evidence) <= produces else UNSATISFIED


def derive_result(checks: dict[str, str]) -> str:
    """Aggregate per-aspect four-state checks into one result. Only 'satisfied' satisfies:
    any error → error; any unsatisfied → unsatisfied; any unknown → unknown; else satisfied.
    An empty check set is unknown (nothing was determined)."""
    values = set(checks.values())
    if not values:
        return UNKNOWN
    for dominant in (ERROR, UNSATISFIED, UNKNOWN):
        if dominant in values:
            return dominant
    return SATISFIED


@dataclass(slots=True)
class ContractCheck:
    """The reified result of checking an invocation against a CapabilityDefinition's contracts
    (proposal 0051; schemas/contract-check.schema.json). ``checks`` maps aspect → four-state
    (input/output/effect); ``result`` is derived and never silently satisfied."""

    definition_id: str
    checks: dict[str, str]
    result: str
    id: str = field(default_factory=lambda: new_id("ctr"))
    checked_at: str = field(default_factory=utc_now)

    STATES: ClassVar[frozenset[str]] = STATES

    def __post_init__(self) -> None:
        bad = {v for v in self.checks.values()} | {self.result}
        if bad - STATES:
            raise ValueError(f"contract states must be within {sorted(STATES)}")

    def is_satisfied(self) -> bool:
        return self.result == SATISFIED

    def to_dict(self) -> JSON:
        return asdict(self)


def check_contract(
    definition: CapabilityDefinition,
    *,
    input: JSON | None = None,
    output: JSON | None = None,
    effect_class: str | None = None,
) -> ContractCheck:
    """Check the provided aspects of an invocation against ``definition`` and reify the result.
    Only aspects passed are checked (a caller may check input at admission, output at completion)."""
    checks: dict[str, str] = {}
    if input is not None:
        checks["input"] = validate_input(definition, input)
    if output is not None:
        checks["output"] = validate_output(definition, output)
    if effect_class is not None:
        checks["effect"] = check_effect(definition, effect_class)
    return ContractCheck(
        definition_id=f"{definition.id}@{definition.version}",
        checks=checks,
        result=derive_result(checks),
    )
