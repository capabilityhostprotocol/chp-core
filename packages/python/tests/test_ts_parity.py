"""Cross-language BUILD parity: TypeScript builds → Python verifies.

The published vectors prove Python-built objects verify under TS; this proves
the reverse direction for the statement family the SDK can now build
(mandates §10, adapter provenance §9, rotation continuity §3.2). Skipped when
node or the built SDK dist is unavailable (CI builds the SDK first).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SDK_DIST = REPO / "packages" / "chp-sdk" / "dist" / "index.js"

_NODE_SCRIPT = """
const sdk = require(process.argv[1]);
const key = sdk.keypairFromSeed(Buffer.from(Array.from({length: 32}, (_, i) => i + 42)));
const newKey = sdk.keypairFromSeed(Buffer.from(Array.from({length: 32}, (_, i) => i + 142)));
const TS = "2026-01-01T00:00:00Z";
const out = {
  mandate: sdk.buildMandate("ts-principal", key, {
    delegateId: "py-verifier", scope: ["cross.check", "chp.adapters.audit.*"],
    validFrom: TS, validUntil: "2027-01-01T00:00:00Z", createdAt: TS,
    mandateId: "mnd_ts_parity",
  }),
  provenance: sdk.buildProvenanceStatement(
    "chp-adapter-parity", "0.0.1", "cd".repeat(32), key,
    {publisherId: "ts-publisher", createdAt: TS}),
  continuity: sdk.buildContinuityStatement(key, newKey, TS),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ts_built() -> dict:
    if shutil.which("node") is None:
        pytest.skip("node unavailable")
    if not SDK_DIST.exists():
        pytest.skip("chp-sdk dist not built (npm run build in packages/chp-sdk)")
    if "buildMandate" not in SDK_DIST.read_text():
        # A checkout can carry a STALE dist (build artifacts aren't part of
        # source sync) — skip rather than fail on pre-parity builds.
        pytest.skip("chp-sdk dist is stale (rebuild: npm run build in packages/chp-sdk)")
    proc = subprocess.run(
        ["node", "-e", _NODE_SCRIPT, str(SDK_DIST)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"node emitter failed: {proc.stderr[-500:]}"
    return json.loads(proc.stdout)


def test_ts_built_mandate_verifies_in_python(ts_built):
    from chp_core.signing import verify_mandate

    v = verify_mandate(
        ts_built["mandate"], at_time="2026-06-01T00:00:00Z",
        capability_id="cross.check", delegate_id="py-verifier")
    assert v.valid, f"TS-built mandate must verify under Python: {v.reason}"
    assert v.checks["principal_identity"] is True

    tampered = dict(ts_built["mandate"])
    tampered["scope"] = ["*"]
    assert verify_mandate(tampered).checks["signature"] is False


def test_ts_built_provenance_verifies_in_python(ts_built):
    from chp_core.signing import verify_provenance_statement

    v = verify_provenance_statement(
        ts_built["provenance"], wheel_sha256="cd" * 32)
    assert v.valid, f"TS-built provenance must verify under Python: {v.reason}"
    assert v.checks["artifact_hash"] is True


def test_ts_built_continuity_verifies_in_python(ts_built):
    from chp_core.signing import verify_continuity

    assert verify_continuity(ts_built["continuity"]) is True
    bad = dict(ts_built["continuity"])
    bad["new_key_id"] = "deadbeef"
    assert verify_continuity(bad) is False
