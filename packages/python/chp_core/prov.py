"""W3C PROV export — CHP evidence as signed, governed provenance.

CHP's evidence *is* provenance: an invocation is a prov:Activity, its `subject`
a prov:Agent, its output a prov:Entity, and the causal edge (causation_id) a
prov:wasInformedBy link. This exporter serializes a replayed correlation as
PROV-JSON (the W3C PROV-JSON serialization) so CHP interoperates with lineage
and catalog tooling — while carrying the two things PROV/OpenLineage lack:

- **Governance** — denial, risk/safety, approval, budget as chp: annotations on
  the Activity. PROV has no vocabulary for a *refusal*; CHP exports it anyway.
- **Integrity** — the content_hash tamper anchor as a chp: annotation on the
  Entity. "Signed, governed provenance" — see docs/comparisons/chp-and-w3c-prov.md.

The native signed CHP plane stays source of truth; PROV is a bridge out.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .otel import _governance_attributes
from .types import JSON

CHP_PROV_NS = "https://chp.dev/prov#"


def _prov_governance(events: list[JSON]) -> dict[str, Any]:
    """Reuse the OTel governance surface, remapped to PROV attribute names
    (``chp.safety.blocked`` -> ``chp:safety_blocked``)."""
    return {
        "chp:" + key[len("chp."):].replace(".", "_"): value
        for key, value in _governance_attributes(events).items()
    }


def replay_to_prov(events: list[JSON]) -> JSON:
    """Serialize a replayed correlation's events as a PROV-JSON document."""
    grouped: dict[str, list[JSON]] = defaultdict(list)
    for event in events:
        grouped[event["invocation_id"]].append(event)

    activities: dict[str, JSON] = {}
    agents: dict[str, JSON] = {}
    entities: dict[str, JSON] = {}
    associations: dict[str, JSON] = {}
    generations: dict[str, JSON] = {}
    informed: dict[str, JSON] = {}
    n = 0

    for invocation_id, inv_events in grouped.items():
        first, last = inv_events[0], inv_events[-1]
        correlation = first.get("correlation") or {}
        act_id = f"chp:{invocation_id}"

        # Activity — the invocation, with outcome + governance annotations.
        activity: JSON = {
            "prov:startTime": first["timestamp"],
            "prov:endTime": last["timestamp"],
            "chp:capability_id": first["capability_id"],
            "chp:correlation_id": correlation.get("correlation_id"),
            "chp:outcome": last.get("outcome"),
            "chp:denied": last.get("event_type") == "execution_denied",
        }
        denial = last.get("denial") or {}
        if denial.get("code"):
            activity["chp:denial_code"] = denial["code"]
        activity.update(_prov_governance(inv_events))
        activities[act_id] = activity

        # Agent — the subject the invocation acted for + the host (softwareAgent).
        subject = first.get("subject") or {}
        subject_id = subject.get("id") or "unknown"
        agent_id = f"chp:agent:{subject_id}"
        agents.setdefault(agent_id, {
            "prov:type": "prov:Agent",
            "chp:subject_type": subject.get("type"),
            "chp:verified": subject.get("verified", False),
        })
        host_id = f"chp:host:{first['host_id']}"
        agents.setdefault(host_id, {"prov:type": "prov:SoftwareAgent"})

        associations[f"_:wa{n}"] = {"prov:activity": act_id, "prov:agent": agent_id}
        associations[f"_:wah{n}"] = {"prov:activity": act_id, "prov:agent": host_id}

        # Entity — the tamper-evident evidence record, anchored by content_hash.
        content_hash = last.get("content_hash") or first.get("content_hash")
        ent_id = f"chp:evidence:{invocation_id}"
        entities[ent_id] = {
            "prov:type": "chp:EvidenceRecord",
            "chp:content_hash": content_hash,
            "chp:hash_chained": content_hash is not None,
        }
        generations[f"_:wg{n}"] = {"prov:entity": ent_id, "prov:activity": act_id}

        # Causal edge — child activity was informed by its parent (causation_id).
        causation_id = correlation.get("causation_id")
        if causation_id:
            informed[f"_:wi{n}"] = {
                "prov:informed": act_id, "prov:informant": f"chp:{causation_id}",
            }
        n += 1

    doc: JSON = {
        "prefix": {"chp": CHP_PROV_NS},
        "activity": activities,
        "agent": agents,
        "entity": entities,
        "wasAssociatedWith": associations,
        "wasGeneratedBy": generations,
    }
    if informed:
        doc["wasInformedBy"] = informed
    return doc
