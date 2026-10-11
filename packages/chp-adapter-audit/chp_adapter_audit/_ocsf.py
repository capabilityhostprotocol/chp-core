"""Map CHP governed decisions / effect records to OCSF (Open Cybersecurity Schema Framework) events.

Any CHP host records governed decisions as native evidence (a capability was allowed or denied, a
secret was brokered, an external effect was mediated). Emitting those decisions in the OCSF **API
Activity** class (category_uid 6, class_uid 6003) lets a SIEM / auditor ingest CHP evidence with no
CHP-specific parser. This is the generic, ecosystem-wide mapping — it is grounded on OCSF 1.3.0
(schema.ocsf.io): ``type_uid = class_uid*100 + activity_id``; ``status_id`` 1=Success / 2=Failure;
``severity_id`` 0-6/99.

Honest scope: an OCSF-*aligned* mapping carrying the core envelope + the CHP decision preserved as an
enrichment, validated against OCSF 1.3.0's documented required-attribute set + enums — NOT a
byte-for-byte run against the published JSON Schema (no network at verify time), and not a claim of
certified conformance.

Pure (no host / store / I/O): the ``ocsf_export`` capability wraps this and adds governed evidence.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Sequence

OCSF_VERSION = "1.3.0"
CATEGORY_UID_APPLICATION_ACTIVITY = 6
CLASS_UID_API_ACTIVITY = 6003
ACTIVITY_READ = 2          # a read of an external resource on the agent's behalf (e.g. http.get)
ACTIVITY_OTHER = 99        # secret brokerage / capability invocation / anything non-read
STATUS_SUCCESS = 1
STATUS_FAILURE = 2
SEVERITY_INFORMATIONAL = 1
SEVERITY_MEDIUM = 3        # a denied effect is more notable than an allowed one

# Default product metadata; a caller may override per export (e.g. a product name).
DEFAULT_PRODUCT = {"name": "CHP Audit", "vendor_name": "Capability Host Protocol"}

# ops that READ an external resource (OCSF activity_id 2); everything else is OTHER (99).
_READ_OPS = frozenset({"http.get", "read", "get", "fetch"})


def _activity_for(op: str) -> int:
    return ACTIVITY_READ if op in _READ_OPS else ACTIVITY_OTHER


def decision_to_ocsf(
    decision: Mapping[str, Any],
    *,
    source: str = "chp-host",
    product: Mapping[str, Any] | None = None,
    op: str | None = None,
) -> dict:
    """Map one governed decision to an OCSF API Activity event.

    ``decision`` is a CHP decision/effect record — recognized keys: ``op`` (operation kind),
    ``decision`` (``ALLOW``/``DENY``), ``capability`` or ``secret_ref`` (the governed target). Any
    other keys are preserved verbatim inside the ``chp.governed_decision`` enrichment, not dropped.
    ``source`` identifies the producing component (host id, cell id, product name).
    """
    op = op or str(
        decision.get("op")
        or ("capability" if decision.get("capability") else
            "secret" if decision.get("secret_ref") else "effect")
    )
    allowed = str(decision.get("decision", "")).upper() == "ALLOW"
    activity_id = _activity_for(op)
    operation = str(decision.get("capability") or decision.get("secret_ref") or op)
    prod = dict(product) if product else dict(DEFAULT_PRODUCT)
    event = {
        "category_uid": CATEGORY_UID_APPLICATION_ACTIVITY,
        "class_uid": CLASS_UID_API_ACTIVITY,
        "activity_id": activity_id,
        "type_uid": CLASS_UID_API_ACTIVITY * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL if allowed else SEVERITY_MEDIUM,
        "status_id": STATUS_SUCCESS if allowed else STATUS_FAILURE,
        "status": "ALLOW" if allowed else "DENY",
        "time": int(time.time() * 1000),
        "metadata": {"version": OCSF_VERSION, "product": prod},
        "actor": {"app_name": source, "process": {"name": f"source:{source}"}},
        "api": {"operation": operation, "service": {"name": "chp-governed-host"}},
        "src_endpoint": {"svc_name": source},
        # OCSF API Activity marks `cloud` and `osint` required; a CHP host runs on-prem by default,
        # with no OSINT indicators — represent that honestly rather than omit a required field.
        "cloud": {"provider": "on-prem"},
        "osint": [],
        # CHP-specific enrichment: the governed decision, preserved verbatim for auditors.
        "enrichments": [
            {"name": "chp.governed_decision", "provider": "chp-audit", "data": dict(decision)}
        ],
    }
    return event


def decisions_to_ocsf(
    decisions: Sequence[Mapping[str, Any]],
    *,
    source: str = "chp-host",
    product: Mapping[str, Any] | None = None,
) -> list[dict]:
    return [decision_to_ocsf(d, source=source, product=product) for d in decisions]


_REQUIRED_CORE = ("category_uid", "class_uid", "activity_id", "type_uid", "severity_id",
                  "status_id", "time", "metadata")

# OCSF 1.3.0 API Activity: the attributes the schema marks `requirement: required` (status_id/status
# are only recommended). Grounded on schema.ocsf.io/1.3.0/classes/api_activity.
_REQUIRED_API_ACTIVITY = ("activity_id", "category_uid", "class_uid", "type_uid", "severity_id",
                          "time", "metadata", "actor", "api", "cloud", "osint", "src_endpoint")
_ACTIVITY_IDS = frozenset({0, 1, 2, 3, 4, 99})
_SEVERITY_IDS = frozenset({0, 1, 2, 3, 4, 5, 6, 99})
_STATUS_IDS = frozenset({0, 1, 2, 99})


def validate_ocsf_core(event: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Check the OCSF core envelope: required fields present, type_uid consistent, metadata has a
    version + product. (Shape validation, not full OCSF JSON-schema conformance.)"""
    missing = [f for f in _REQUIRED_CORE if f not in event]
    problems = list(missing)
    if "type_uid" in event and "class_uid" in event and "activity_id" in event:
        if event["type_uid"] != event["class_uid"] * 100 + event["activity_id"]:
            problems.append("type_uid != class_uid*100 + activity_id")
    md = event.get("metadata") or {}
    if "version" not in md:
        problems.append("metadata.version missing")
    if "product" not in md:
        problems.append("metadata.product missing")
    return (not problems, problems)


def ocsf_conformance(event: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Validate an OCSF **API Activity** event against OCSF 1.3.0's documented requirements: every
    `required` attribute present, the class/category/type_uid identity, and the activity/severity/status
    enum ranges, plus the required sub-fields of metadata/actor/api/cloud/src_endpoint.

    This validates against OCSF's documented required-attribute set + enums; it is not a byte-for-byte
    run against the published JSON Schema file (no network at verify time)."""
    p: list[str] = [f"missing required: {f}" for f in _REQUIRED_API_ACTIVITY if f not in event]
    if event.get("category_uid") != CATEGORY_UID_APPLICATION_ACTIVITY:
        p.append("category_uid != 6 (Application Activity)")
    if event.get("class_uid") != CLASS_UID_API_ACTIVITY:
        p.append("class_uid != 6003 (API Activity)")
    if event.get("activity_id") not in _ACTIVITY_IDS:
        p.append(f"activity_id {event.get('activity_id')!r} not a valid enum")
    if {"type_uid", "class_uid", "activity_id"} <= set(event) and \
            event["type_uid"] != event["class_uid"] * 100 + event["activity_id"]:
        p.append("type_uid != class_uid*100 + activity_id")
    if event.get("severity_id") not in _SEVERITY_IDS:
        p.append(f"severity_id {event.get('severity_id')!r} not a valid enum")
    if "status_id" in event and event["status_id"] not in _STATUS_IDS:
        p.append(f"status_id {event.get('status_id')!r} not a valid enum")
    if not isinstance(event.get("osint"), list):
        p.append("osint must be an array")
    md = event.get("metadata") or {}
    if "version" not in md:
        p.append("metadata.version missing")
    if not (md.get("product") or {}).get("vendor_name"):
        p.append("metadata.product.vendor_name missing")
    if not (event.get("cloud") or {}).get("provider"):
        p.append("cloud.provider missing")
    if not (event.get("api") or {}).get("operation"):
        p.append("api.operation missing")
    if not event.get("actor"):
        p.append("actor missing")
    if not event.get("src_endpoint"):
        p.append("src_endpoint missing")
    return (not p, p)
