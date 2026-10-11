"""Result-cache coverage lint (governance).

The §13 idempotent-replay cache is correctly default-ON (it dedupes retried invocations, preventing
double-execution of side-effecting capabilities). A capability that RETURNS sensitive data must opt
OUT so its value never persists at rest, via descriptor ``metadata={"cache_results": False}`` — which
``chp.adapters.secrets.get`` does. The opt-out is the mechanism; this lint is the COVERAGE check:
it flags a capability that *looks* like it returns secrets/credentials but forgot the flag, so a
future sensitive cap can't silently leak into the cache. It is a conformance/audit helper — it reads
descriptors, changes no behavior.
"""

from __future__ import annotations

from typing import Any, Iterable

# A capability is "sensitivity-suspect" when its id / category / tags carry one of these hints. Kept
# deliberately broad + fail-loud: a false positive is resolved by setting cache_results (True or
# False) explicitly; a missed sensitive cap is the thing we must not allow.
_SENSITIVE_HINTS: tuple[str, ...] = (
    "secret", "credential", "creds", "token", "password", "passwd", "apikey", "api_key",
    "api-key", "vault", "private_key", "privatekey", "bearer",
)


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """Read a field from a descriptor object OR a discover()-style dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def is_sensitivity_suspect(descriptor: Any) -> bool:
    cid = str(_field(descriptor, "id", "") or "")
    category = str(_field(descriptor, "category", "") or "")
    tags = _field(descriptor, "tags", None) or []
    hay = " ".join([cid, category, " ".join(str(t) for t in tags)]).lower()
    return any(hint in hay for hint in _SENSITIVE_HINTS)


def result_cache_coverage_violations(descriptors: Iterable[Any]) -> list[dict]:
    """Return a finding per capability that looks sensitive but does NOT set
    ``metadata['cache_results'] is False`` — i.e. whose result could persist in the §13 cache.

    The cache stores a result unless ``cache_results`` is exactly ``False`` — so an ABSENT flag and an
    explicit ``True`` both leave a sensitive value cacheable. The only safe state for a
    sensitivity-suspect capability is an explicit ``False``; anything else is flagged (a genuinely
    non-sensitive cap that trips the name heuristic is resolved by setting ``False`` — harmless, it
    just won't be cached — or by retagging away from the sensitive hint)."""
    violations: list[dict] = []
    for d in descriptors:
        meta = _field(d, "metadata", None) or {}
        if meta.get("cache_results") is False:   # the one safe state: value never persists at rest
            continue
        if is_sensitivity_suspect(d):
            violations.append({
                "capability_id": str(_field(d, "id", "?") or "?"),
                "reason": "sensitivity-suspect capability does not set metadata cache_results=False — "
                          "its result could persist in the §13 replay cache (an explicit True caches "
                          "it too); set cache_results=False, or retag if it returns nothing sensitive",
            })
    return violations
