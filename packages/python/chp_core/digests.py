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


def _is_sha256(value: object) -> bool:
    """A ``sha256:`` + 64-hex digest string (the machine-contract digest shape)."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    hexpart = value[len("sha256:"):]
    return len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart)


def dual_digest_consistent(
    action_digest: object, invocation_digest: object, *, document: JSON | None = None
) -> bool:
    """Verify the 0043 dual-digest INVARIANT on a received pair (CHP-CORE-026) — the machine-contract
    teeth a JSON Schema cannot express.

    A JSON Schema can only assert each digest is a sha256 string; it cannot assert the two RELATE
    correctly. A genuine ``invocation_digest`` is the digest of an invocation document that CONTAINS
    ``action_digest`` plus routing, so it can never equal ``action_digest`` — a collapsed pair
    (``action_digest == invocation_digest``) is a forgery that defeats the whole action/invocation
    separation yet passes the shape schema. This checks, in order:

    - both are well-formed sha256 digests;
    - they are DISTINCT (a collapsed pair is rejected);
    - when the full canonical invocation ``document`` is supplied, it carries exactly the claimed
      ``action_digest`` AND its recomputed digest equals the claimed ``invocation_digest`` (so the pair
      is not merely distinct but actually derived — a swapped-routing tamper is caught, CHP-CORE-006).

    Returns ``False`` rather than raising, so a relying validator treats an inconsistent pair as a
    rejection on its normal path, never an exception. Reuses ``_digest``/``_canon_jcs`` — no new
    canonicalization, so a second implementation agrees byte-for-byte (CHP-CORE-024)."""
    if not (_is_sha256(action_digest) and _is_sha256(invocation_digest)):
        return False
    if action_digest == invocation_digest:
        return False  # collapsed pair — never a genuine 0043 derivation
    if document is not None:
        if document.get("action_digest") != action_digest:
            return False  # the document does not carry the claimed action_digest
        try:
            if _digest(document) != invocation_digest:
                return False  # invocation_digest does not recompute from the document (tampered routing)
        except (ValueError, TypeError):
            return False
    return True
