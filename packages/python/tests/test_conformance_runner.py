"""Self-tests: conformance runner must pass on passing sample and fail on broken samples."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER = REPO_ROOT / "conformance" / "runner.py"


def _run(sample: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RUNNER), "--sample", sample],
        capture_output=True,
        text=True,
        timeout=60,
    )


class ConformanceRunnerSelfTests(unittest.TestCase):
    def test_passing_sample_exits_zero(self) -> None:
        result = _run("passing")
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_failing_non_standard_codes_exits_nonzero(self) -> None:
        result = _run("failing-non-standard-codes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL standard denial codes", result.stdout)

    def test_failing_no_hash_chain_exits_nonzero(self) -> None:
        result = _run("failing-no-hash-chain")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL evidence hash chain", result.stdout)

    def test_failing_no_evidence_exits_nonzero(self) -> None:
        result = _run("failing-no-evidence")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
