from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core.adapters import HostedCapability, register_hosted_capabilities  # noqa: E402
from chp_core.cli import main as cli_main  # noqa: E402
from chp_core.host import LocalCapabilityHost  # noqa: E402
from chp_core.store import SQLiteEvidenceStore  # noqa: E402
from chp_core.types import CapabilityDescriptor  # noqa: E402


class WorkCLITests(unittest.TestCase):
    def test_adapter_registers_capabilities_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            host = LocalCapabilityHost(store=SQLiteEvidenceStore(str(Path(tmpdir) / "adapter.sqlite")))

            async def handler(_ctx, _payload):
                return {"ok": True}

            capability = HostedCapability(
                CapabilityDescriptor(
                    id="test.adapter.echo",
                    version="0.1.0",
                    description="Adapter test capability.",
                    input_schema={"type": "object"},
                    output_schema={"type": "object"},
                ),
                handler,
            )

            first = register_hosted_capabilities(host, [capability])
            second = register_hosted_capabilities(host, [capability])

            self.assertEqual([descriptor.id for descriptor in first], ["test.adapter.echo"])
            self.assertEqual(second, [])
            self.assertEqual(
                [item["id"] for item in host.discover()["capabilities"]],
                ["test.adapter.echo"],
            )

    def test_record_summary_replay_and_explain_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-work-cli"

            record = self.run_cli(
                [
                    "work",
                    "record",
                    "--store",
                    store,
                    "--intent",
                    "Record CLI work evidence.",
                    "--correlation-id",
                    correlation_id,
                    "--file-inspected",
                    "packages/python/chp_core/cli.py",
                    "--file-changed",
                    "packages/python/chp_core/work.py",
                    "--command-run",
                    "python -m unittest",
                    "--test-run",
                    "unit",
                    "--follow-up",
                    "Run conformance.",
                ]
            )
            self.assertTrue(record["success"])
            self.assertEqual(record["outcome"], "success")

            summary = self.run_cli(["work", "summary", correlation_id, "--store", store])
            self.assertEqual(summary["action_count"], 1)
            self.assertEqual(
                summary["files_changed"],
                ["packages/python/chp_core/work.py"],
            )
            self.assertEqual(summary["tests_run"], ["unit"])

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(replay["event_count"], 3)

            explanation = self.run_cli(["work", "explain", correlation_id, "--store", store])
            self.assertTrue(explanation["success"])
            self.assertEqual(explanation["data"]["correlation_id"], correlation_id)

    def test_run_records_command_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            result = self.run_cli(
                [
                    "work",
                    "run",
                    "--store",
                    store,
                    "--intent",
                    "Run a small command.",
                    "--correlation-id",
                    "corr-work-run",
                    "--",
                    sys.executable,
                    "-c",
                    "print('ok')",
                ]
            )
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["stdout_preview"].strip(), "ok")
            self.assertEqual(result["recorded"]["outcome"], "success")

            summary = self.run_cli(["work", "summary", "corr-work-run", "--store", store])
            self.assertEqual(summary["latest_outcome"], "success")
            self.assertIn(sys.executable, summary["commands_run"][0])

    def test_validate_endpoint_demo_records_validation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-validate-demo"

            validation = self.run_cli(
                [
                    "work",
                    "validate-demo",
                    "endpoint",
                    "--store",
                    store,
                    "--correlation-id",
                    correlation_id,
                ]
            )

            self.assertTrue(validation["success"])
            self.assertTrue(validation["data"]["passed"])
            self.assertEqual(
                [check["name"] for check in validation["data"]["checks"]],
                [
                    "host_discovery",
                    "successful_invocation",
                    "denied_invocation",
                    "replay_contains_evidence",
                    "explanation_references_evidence",
                ],
            )

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                ["execution_started", "demo_validated", "execution_completed"],
            )

    def test_check_alignment_records_alignment_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-check-alignment"

            alignment = self.run_cli(
                [
                    "work",
                    "check-alignment",
                    "--store",
                    store,
                    "--correlation-id",
                    correlation_id,
                ]
            )

            self.assertTrue(alignment["success"])
            self.assertTrue(alignment["data"]["passed"])
            self.assertIn("CapabilityDescriptor", alignment["data"]["core_objects"])
            self.assertEqual(
                alignment["data"]["outcomes"],
                ["success", "failure", "denied", "skipped"],
            )

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "schema_spec_alignment_checked",
                    "execution_completed",
                ],
            )

    def test_check_messaging_records_messaging_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-check-messaging"

            messaging = self.run_cli(
                [
                    "work",
                    "check-messaging",
                    "--store",
                    store,
                    "--correlation-id",
                    correlation_id,
                ]
            )

            self.assertTrue(messaging["success"])
            self.assertTrue(messaging["data"]["passed"])
            self.assertIn("README.md", messaging["data"]["public_files"])
            self.assertIn("docs/onboarding.md", messaging["data"]["legacy_files"])

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "launch_messaging_checked",
                    "execution_completed",
                ],
            )

    def test_inventory_records_agentic_capability_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-agentic-inventory"

            inventory = self.run_cli(
                [
                    "work",
                    "inventory",
                    "--store",
                    store,
                    "--correlation-id",
                    correlation_id,
                ]
            )

            self.assertTrue(inventory["success"])
            self.assertEqual(inventory["outcome"], "success")
            self.assertIn("execution-evidence", inventory["data"]["categories"])
            self.assertIn("trace_execution", [item["id"] for item in inventory["data"]["capabilities"]])
            self.assertIn(
                "chp.audit_evidence_quality",
                [item["id"] for item in inventory["data"]["capabilities"]],
            )

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "agentic_capability_inventory_generated",
                    "execution_completed",
                ],
            )

    def test_inventory_can_filter_to_implemented_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")

            inventory = self.run_cli(
                [
                    "work",
                    "inventory",
                    "--store",
                    store,
                    "--correlation-id",
                    "corr-implemented-inventory",
                    "--implemented-only",
                ]
            )

            ids = [item["id"] for item in inventory["data"]["capabilities"]]
            self.assertIn("chp.inventory_agentic_capabilities", ids)
            self.assertIn("chp.audit_evidence_quality", ids)
            self.assertIn("chp.version_control.inspect_repo", ids)
            self.assertIn("chp.version_control.verify_merge_readiness", ids)
            self.assertIn("chp.run_conformance_matrix", ids)
            self.assertIn("chp.radicle.patches.merge", ids)
            self.assertEqual(inventory["data"]["status_counts"], {"implemented": 21})

    def test_audit_evidence_quality_records_audit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            target_correlation_id = "corr-audit-target"
            audit_correlation_id = "corr-audit-quality"

            self.run_cli(
                [
                    "work",
                    "record",
                    "--store",
                    store,
                    "--intent",
                    "Seed evidence for audit.",
                    "--correlation-id",
                    target_correlation_id,
                    "--file-changed",
                    "packages/python/chp_core/work.py",
                    "--test-run",
                    "unit",
                ]
            )

            audit = self.run_cli(
                [
                    "work",
                    "audit-evidence",
                    target_correlation_id,
                    "--store",
                    store,
                    "--correlation-id",
                    audit_correlation_id,
                ]
            )

            self.assertTrue(audit["success"])
            self.assertTrue(audit["data"]["passed"])
            self.assertEqual(audit["data"]["target_correlation_id"], target_correlation_id)
            self.assertEqual(audit["data"]["event_count"], 3)
            self.assertEqual(audit["data"]["failed_checks"], [])

            replay = self.run_cli(["work", "replay", audit_correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "evidence_quality_audited",
                    "execution_completed",
                ],
            )

    def test_conformance_matrix_records_conformance_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            correlation_id = "corr-conformance-matrix"

            matrix = self.run_cli(
                [
                    "work",
                    "conformance-matrix",
                    "--store",
                    store,
                    "--correlation-id",
                    correlation_id,
                    "--target",
                    "sample-passing",
                    "--target",
                    "sample-failing-no-evidence",
                    "--target",
                    "work-host",
                ]
            )

            self.assertTrue(matrix["success"])
            self.assertTrue(matrix["data"]["passed"])
            self.assertEqual(matrix["data"]["target_count"], 3)
            self.assertEqual(matrix["data"]["failed_targets"], [])
            self.assertEqual(
                [target["target"] for target in matrix["data"]["targets"]],
                ["sample-passing", "sample-failing-no-evidence", "work-host"],
            )
            self.assertFalse(matrix["data"]["targets"][1]["observed_success"])

            replay = self.run_cli(["work", "replay", correlation_id, "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "conformance_matrix_completed",
                    "execution_completed",
                ],
            )

    def test_audit_evidence_quality_fails_missing_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = str(Path(tmpdir) / "work.sqlite")
            output = StringIO()
            with redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "work",
                        "audit-evidence",
                        "missing-correlation",
                        "--store",
                        store,
                        "--correlation-id",
                        "corr-audit-missing",
                    ]
                )

            self.assertEqual(exit_code, 1)
            audit = json.loads(output.getvalue())
            self.assertFalse(audit["data"]["passed"])
            self.assertIn("trace_has_events", audit["data"]["failed_checks"])

    def test_version_control_inspect_diff_and_precommit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            store = str(root / "work.sqlite")
            self.init_git_repo(repo)

            tracked = repo / "tracked.txt"
            tracked.write_text("updated\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("new\n", encoding="utf-8")

            inspect = self.run_cli(
                [
                    "work",
                    "vc",
                    "inspect",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-inspect",
                ]
            )
            self.assertTrue(inspect["success"])
            self.assertTrue(inspect["data"]["is_repo"])
            self.assertFalse(inspect["data"]["clean"])
            self.assertIn("untracked.txt", inspect["data"]["untracked_files"])

            diff = self.run_cli(
                [
                    "work",
                    "vc",
                    "diff",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-diff",
                ]
            )
            self.assertTrue(diff["success"])
            self.assertTrue(diff["data"]["redacted_patch"])
            self.assertGreaterEqual(diff["data"]["changed_file_count"], 2)
            self.assertIsNone(diff["data"]["patch"])

            precommit = self.run_cli(
                [
                    "work",
                    "vc",
                    "precommit",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-precommit",
                    "--check",
                    f"{sys.executable} -c \"print('ok')\"",
                ]
            )
            self.assertTrue(precommit["success"])
            self.assertTrue(precommit["data"]["passed"])
            self.assertEqual(precommit["data"]["checks"][0]["stdout_preview"].strip(), "ok")

            replay = self.run_cli(["work", "replay", "corr-vc-precommit", "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "version_control_precommit_checked",
                    "execution_completed",
                ],
            )

    def test_version_control_release_bundle_includes_work_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            store = str(root / "work.sqlite")
            self.init_git_repo(repo)

            self.run_cli(
                [
                    "work",
                    "record",
                    "--store",
                    store,
                    "--intent",
                    "Seed work trace for release bundle.",
                    "--correlation-id",
                    "corr-vc-work",
                    "--file-changed",
                    "tracked.txt",
                ]
            )

            bundle = self.run_cli(
                [
                    "work",
                    "vc",
                    "release-bundle",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-release",
                    "--include-correlation",
                    "corr-vc-work",
                    "--check",
                    f"{sys.executable} -c \"print('release ok')\"",
                ]
            )

            self.assertTrue(bundle["success"])
            self.assertTrue(bundle["data"]["passed"])
            self.assertEqual(bundle["data"]["work_traces"][0]["correlation_id"], "corr-vc-work")
            self.assertTrue(bundle["data"]["repo"]["clean"])

    def test_version_control_merge_readiness_passes_with_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            store = str(root / "work.sqlite")
            self.init_git_repo(repo)

            self.run_cli(
                [
                    "work",
                    "record",
                    "--store",
                    store,
                    "--intent",
                    "Seed work trace for merge readiness.",
                    "--correlation-id",
                    "corr-vc-ready-work",
                    "--file-changed",
                    "tracked.txt",
                ]
            )

            self.run_cli(
                [
                    "work",
                    "vc",
                    "release-bundle",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-ready-release",
                    "--include-correlation",
                    "corr-vc-ready-work",
                    "--check",
                    f"{sys.executable} -c \"print('release ok')\"",
                ]
            )

            readiness = self.run_cli(
                [
                    "work",
                    "vc",
                    "merge-readiness",
                    "--store",
                    store,
                    "--repo-root",
                    str(repo),
                    "--correlation-id",
                    "corr-vc-ready",
                    "--include-correlation",
                    "corr-vc-ready-work",
                    "--release-correlation-id",
                    "corr-vc-ready-release",
                    "--require-approval",
                    "--approval",
                    "--check",
                    f"{sys.executable} -c \"print('ready ok')\"",
                ]
            )

            self.assertTrue(readiness["success"])
            self.assertTrue(readiness["data"]["ready"])
            self.assertEqual(readiness["data"]["decision"], "ready")
            self.assertEqual(readiness["data"]["failed_checks"], [])

            replay = self.run_cli(["work", "replay", "corr-vc-ready", "--store", store])
            self.assertEqual(
                [event["event_type"] for event in replay["events"]],
                [
                    "execution_started",
                    "version_control_merge_readiness_verified",
                    "execution_completed",
                ],
            )

    def test_version_control_merge_readiness_blocks_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            store = str(root / "work.sqlite")
            self.init_git_repo(repo)
            (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "work",
                        "vc",
                        "merge-readiness",
                        "--store",
                        store,
                        "--repo-root",
                        str(repo),
                        "--correlation-id",
                        "corr-vc-not-ready",
                        "--check",
                        f"{sys.executable} -c \"print('ready ok')\"",
                    ]
                )

            self.assertEqual(exit_code, 1)
            readiness = json.loads(output.getvalue())
            self.assertTrue(readiness["success"])
            self.assertFalse(readiness["data"]["ready"])
            self.assertEqual(readiness["data"]["decision"], "not_ready")
            self.assertIn("worktree_clean", readiness["data"]["failed_checks"])

    @staticmethod
    def run_cli(argv: list[str]):
        output = StringIO()
        with redirect_stdout(output):
            exit_code = cli_main(argv)
        if exit_code != 0:
            raise AssertionError(f"CLI exited with {exit_code}: {output.getvalue()}")
        return json.loads(output.getvalue())

    @staticmethod
    def init_git_repo(repo: Path) -> None:
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.email", "chp@example.test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "CHP Test"], cwd=repo, check=True)
        (repo / "tracked.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
