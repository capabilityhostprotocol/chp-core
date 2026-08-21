"""Canonical action/invocation documents and their digests (proposal 0043).

The execution-truth keystone: a governed invocation carries TWO distinct digests.

- ``action_digest`` identifies the SEMANTIC action — capability + principal + input +
  semantic_context. Provider/host/binding are EXCLUDED because they are routing /
  governance, not semantic action (01_core/02 §Canonical action document). Substituting
  a provider therefore leaves ``action_digest`` UNCHANGED (CHP-CORE-004/006).
- ``invocation_digest`` binds the exact governed attempt — invocation identity plus the
  governance-relevant routing (actor/binding/provider/host). Any routing change CHANGES
  it and requires new admission (CHP-CORE-005/007).

Both use chp-jcs-v1 (RFC 8785 JCS) — the same canonicalization rule as header signatures
(signing.py) — so a second implementation reproduces the digests byte-for-byte
(CHP-CORE-024). Golden vector: docs/product/.../07_conformance/vectors/h1_digest_vector.json.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .signing import _canon_jcs  # reuse the one canonicalization, do not re-implement it

_PROTOCOL = "chp/0.1"

JSON = dict[str, Any]


def _digest(document: JSON) -> str:
    return "sha256:" + hashlib.sha256(_canon_jcs(document)).hexdigest()


def action_document(
    *,
    capability: JSON,
    principal: JSON,
    action_input: JSON | None = None,
    semantic_context: JSON | None = None,
    protocol: str = _PROTOCOL,
) -> JSON:
    """The canonical semantic-action document. Routing (provider/host/binding) is
    deliberately absent — a fact whose change must NOT re-key the semantic action."""
    return {
        "protocol": protocol,
        "capability": capability,
        "principal": principal,
        "input": action_input or {},
        "semantic_context": semantic_context or {},
    }


def action_digest(**kwargs: Any) -> str:
    """sha256: digest of the canonical action document."""
    return _digest(action_document(**kwargs))


def invocation_document(
    *,
    invocation_id: str,
    action_digest: str,
    actor: JSON,
    principal: JSON,
    binding: JSON,
    provider: JSON,
    host: JSON,
    governance_context: JSON | None = None,
    protocol: str = _PROTOCOL,
) -> JSON:
    """The canonical governed-attempt document: invocation identity + the
    governance-relevant routing. A change to any routing field changes the
    resulting invocation_digest and requires fresh admission."""
    return {
        "protocol": protocol,
        "invocation_id": invocation_id,
        "action_digest": action_digest,
        "actor": actor,
        "principal": principal,
        "binding": binding,
        "provider": provider,
        "host": host,
        "governance_context": governance_context or {},
    }


def invocation_digest(**kwargs: Any) -> str:
    """sha256: digest of the canonical invocation document."""
    return _digest(invocation_document(**kwargs))


def binding_document(
    *,
    capability: JSON,
    provider: JSON,
    host: JSON,
    protocol: str = _PROTOCOL,
) -> JSON:
    """Canonical CapabilityBinding identity document: WHAT (capability) supplied by
    WHOM (provider) WHERE (host). Its digest is a stable, content-addressed binding
    id — used to synthesize a binding for a self-hosted invocation without a
    resolver-issued one (proposal 0043)."""
    return {"protocol": protocol, "capability": capability, "provider": provider, "host": host}


def binding_digest(**kwargs: Any) -> str:
    """sha256: content-addressed identity of a CapabilityBinding."""
    return _digest(binding_document(**kwargs))
