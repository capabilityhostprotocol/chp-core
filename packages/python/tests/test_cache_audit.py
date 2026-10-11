"""Result-cache coverage lint: a sensitivity-suspect capability must opt out of the §13 cache
(metadata cache_results=False) or it is flagged."""

from __future__ import annotations

from chp_core import CapabilityDescriptor, LocalCapabilityHost
from chp_core.cache_audit import is_sensitivity_suspect, result_cache_coverage_violations
from chp_core.store import SQLiteEvidenceStore


def _desc(cid, *, metadata=None, tags=None, category=None):
    return CapabilityDescriptor(id=cid, version="1.0.0", description="",
                                metadata=metadata or {}, tags=tags or [], category=category)


def test_sensitive_without_optout_is_flagged():
    v = result_cache_coverage_violations([_desc("x.get_secret")])
    assert [f["capability_id"] for f in v] == ["x.get_secret"]


def test_sensitive_with_optout_false_is_clean():
    assert result_cache_coverage_violations([_desc("x.get_secret", metadata={"cache_results": False})]) == []


def test_sensitive_with_explicit_true_is_still_flagged():
    # True ALSO caches → a sensitive value would persist; only an explicit False is safe
    v = result_cache_coverage_violations([_desc("creds.fetch", metadata={"cache_results": True})])
    assert len(v) == 1


def test_hint_matches_id_tags_or_category():
    assert is_sensitivity_suspect(_desc("x.y", tags=["credential"]))
    assert is_sensitivity_suspect(_desc("x.y", category="auth-token"))
    assert is_sensitivity_suspect(_desc("vault.read"))
    assert not is_sensitivity_suspect(_desc("math.add", tags=["arith"], category="compute"))


def test_non_sensitive_caps_are_clean():
    assert result_cache_coverage_violations([_desc("math.add"), _desc("time.now")]) == []


def test_host_audit_flags_registered_sensitive_cap():
    host = LocalCapabilityHost("audit-host", store=SQLiteEvidenceStore(":memory:"))

    async def h(_ctx, _p):
        return {}

    host.register(_desc("vault.read_token"), h)                                    # sensitive, no opt-out
    host.register(_desc("secrets.get", metadata={"cache_results": False}), h)      # correctly opted out
    host.register(_desc("math.add"), h)                                            # not sensitive
    ids = {f["capability_id"] for f in host.audit_result_cache_coverage()}
    assert "vault.read_token" in ids
    assert "secrets.get" not in ids and "math.add" not in ids
