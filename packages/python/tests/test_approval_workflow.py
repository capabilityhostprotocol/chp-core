"""Tests for v0.3.5 approval workflow completion.

Validates that grant_approval / deny_approval record events in the hash chain
and that chp session autonomy-report correctly classifies pending vs resolved approvals.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chp_core import (
    CapabilityCategory,
    CapabilityDescriptor,
    LocalCapabilityHost,
)
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import AutonomyProfile, new_id


def _host_with_approval_cap(store_path: str) -> tuple[LocalCapabilityHost, str]:
    """Return (host, capability_uri) for an approval_required capability."""
    store = SQLiteEvidenceStore(store_path)
    host = LocalCapabilityHost("test-host", store=store)

    async def _noop(ctx, payload):
        return {"ok": True}

    descriptor = CapabilityDescriptor(
        id="test.gated",
        version="1.0.0",
        description="Approval-required test capability",
        category=CapabilityCategory.AGENT_OPERATIONS,
        autonomy=AutonomyProfile(tier="approval_required"),
    )
    host.register(descriptor, _noop)
    return host, descriptor.capability_uri


class GrantApprovalTests(unittest.TestCase):
    def test_grant_approval_emits_approval_granted_event(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)

            ev = host.grant_approval(sid, cap_uri)
            self.assertEqual(ev.event_type, "approval_granted")

    def test_grant_approval_event_in_chain(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.grant_approval(sid, cap_uri, granted_by="alice")

            events = host.replay(sid)
            event_types = [e["event_type"] for e in events]
            self.assertIn("approval_granted", event_types)

    def test_grant_approval_payload_has_capability_uri(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.grant_approval(sid, cap_uri)

            payload = ev.payload or {}
            self.assertEqual(payload.get("capability_uri"), cap_uri)

    def test_grant_approval_records_granted_by(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.grant_approval(sid, cap_uri, granted_by="alice@example.com")

            self.assertEqual((ev.payload or {}).get("decided_by"), "alice@example.com")

    def test_grant_approval_records_note(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.grant_approval(sid, cap_uri, note="LGTM")

            self.assertEqual((ev.payload or {}).get("note"), "LGTM")

    def test_grant_approval_without_optional_args(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.grant_approval(sid, cap_uri)

            self.assertEqual(ev.event_type, "approval_granted")
            self.assertNotIn("decided_by", ev.payload or {})

    def test_grant_approval_hash_chain_intact(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.grant_approval(sid, cap_uri)

            events = host.store.by_correlation_with_hashes(sid)
            hashes = [e.get("prev_hash") for e in events[1:]]
            self.assertTrue(all(h is not None for h in hashes))


class DenyApprovalTests(unittest.TestCase):
    def test_deny_approval_emits_approval_denied_event(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.deny_approval(sid, cap_uri)

            self.assertEqual(ev.event_type, "approval_denied")

    def test_deny_approval_event_in_chain(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.deny_approval(sid, cap_uri, denied_by="bob")

            events = host.replay(sid)
            event_types = [e["event_type"] for e in events]
            self.assertIn("approval_denied", event_types)

    def test_deny_approval_records_denied_by(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.deny_approval(sid, cap_uri, denied_by="compliance-bot")

            self.assertEqual((ev.payload or {}).get("decided_by"), "compliance-bot")

    def test_deny_approval_records_reason(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.deny_approval(sid, cap_uri, reason="policy violation")

            self.assertEqual((ev.payload or {}).get("reason"), "policy violation")

    def test_deny_approval_payload_has_capability_uri(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            ev = host.deny_approval(sid, cap_uri)

            self.assertEqual((ev.payload or {}).get("capability_uri"), cap_uri)

    def test_deny_approval_hash_chain_intact(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.deny_approval(sid, cap_uri)

            events = host.store.by_correlation_with_hashes(sid)
            hashes = [e.get("prev_hash") for e in events[1:]]
            self.assertTrue(all(h is not None for h in hashes))


class AutonomyReportPendingTests(unittest.TestCase):
    def test_autonomy_report_marks_unresolved_as_pending(self):
        """approval_requested with no grant/deny should count as pending."""
        import io, json, sys
        from chp_core.cli._session import cmd_session_autonomy_report
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, _ = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.store.close()

            args = SimpleNamespace(store=store_path, session_id=sid)
            out = io.StringIO()
            sys.stdout, old = out, sys.stdout
            try:
                rc = cmd_session_autonomy_report(args)
            finally:
                sys.stdout = old

            data = json.loads(out.getvalue())
            self.assertEqual(rc, 0)
            self.assertGreater(data["pending_approvals"], 0)

    def test_autonomy_report_marks_granted_as_resolved(self):
        import io, json, sys
        from chp_core.cli._session import cmd_session_autonomy_report
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.grant_approval(sid, cap_uri)
            host.store.close()

            args = SimpleNamespace(store=store_path, session_id=sid)
            out = io.StringIO()
            sys.stdout, old = out, sys.stdout
            try:
                cmd_session_autonomy_report(args)
            finally:
                sys.stdout = old

            data = json.loads(out.getvalue())
            self.assertEqual(data["pending_approvals"], 0)

    def test_autonomy_report_has_pending_approvals_key(self):
        import io, json, sys
        from chp_core.cli._session import cmd_session_autonomy_report
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, _ = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.store.close()

            args = SimpleNamespace(store=store_path, session_id=sid)
            out = io.StringIO()
            sys.stdout, old = out, sys.stdout
            try:
                cmd_session_autonomy_report(args)
            finally:
                sys.stdout = old

            data = json.loads(out.getvalue())
            self.assertIn("pending_approvals", data)


class ApprovalEventSequenceTests(unittest.TestCase):
    def test_approval_requested_precedes_approval_granted(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid = new_id("sess")
            host.invoke("test.gated", correlation_id=sid)
            host.grant_approval(sid, cap_uri)

            events = host.replay(sid)
            types = [e["event_type"] for e in events]
            req_idx = next(i for i, t in enumerate(types) if t == "approval_requested")
            grant_idx = next(i for i, t in enumerate(types) if t == "approval_granted")
            self.assertLess(req_idx, grant_idx)

    def test_both_grant_and_deny_can_exist_for_different_correlations(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = str(Path(d) / "ev.sqlite")
            host, cap_uri = _host_with_approval_cap(store_path)
            sid_a = new_id("sess")
            sid_b = new_id("sess")
            host.invoke("test.gated", correlation_id=sid_a)
            host.invoke("test.gated", correlation_id=sid_b)
            host.grant_approval(sid_a, cap_uri)
            host.deny_approval(sid_b, cap_uri)

            events_a = host.replay(sid_a)
            events_b = host.replay(sid_b)
            types_a = {e["event_type"] for e in events_a}
            types_b = {e["event_type"] for e in events_b}
            self.assertIn("approval_granted", types_a)
            self.assertNotIn("approval_granted", types_b)
            self.assertIn("approval_denied", types_b)
            self.assertNotIn("approval_denied", types_a)


class ApprovalCLITests(unittest.TestCase):
    """CLI grant-approval and deny-approval commands emit evidence and return rc=0."""

    def _setup_store_with_request(self) -> tuple[str, str, str]:
        """Return (store_path, cap_uri, session_id) with an approval_requested in store."""
        d = tempfile.mkdtemp()
        store_path = str(Path(d) / "ev.sqlite")
        host, cap_uri = _host_with_approval_cap(store_path)
        session_id = new_id("sess")
        host.invoke("test.gated", correlation_id=session_id)
        host.store.close()
        return store_path, cap_uri, session_id

    def test_grant_approval_cli_returns_0(self):
        import argparse
        from chp_core.cli._session import cmd_session_grant_approval

        store_path, cap_uri, session_id = self._setup_store_with_request()
        args = argparse.Namespace(
            session_id=session_id,
            capability_uri=cap_uri,
            by="alice",
            note="looks good",
            store=store_path,
        )
        rc = cmd_session_grant_approval(args)
        self.assertEqual(rc, 0)

    def test_deny_approval_cli_returns_0(self):
        import argparse
        from chp_core.cli._session import cmd_session_deny_approval

        store_path, cap_uri, session_id = self._setup_store_with_request()
        args = argparse.Namespace(
            session_id=session_id,
            capability_uri=cap_uri,
            by="bob",
            reason="too risky",
            store=store_path,
        )
        rc = cmd_session_deny_approval(args)
        self.assertEqual(rc, 0)

    def test_grant_approval_cli_writes_event(self):
        import argparse
        from chp_core.cli._session import cmd_session_grant_approval

        store_path, cap_uri, session_id = self._setup_store_with_request()
        args = argparse.Namespace(
            session_id=session_id, capability_uri=cap_uri,
            by="carol", note=None, store=store_path,
        )
        cmd_session_grant_approval(args)

        store = SQLiteEvidenceStore(store_path)
        events = store.by_correlation(session_id)
        store.close()
        types = {e["event_type"] for e in events}
        self.assertIn("approval_granted", types)

    def test_deny_approval_cli_writes_event(self):
        import argparse
        from chp_core.cli._session import cmd_session_deny_approval

        store_path, cap_uri, session_id = self._setup_store_with_request()
        args = argparse.Namespace(
            session_id=session_id, capability_uri=cap_uri,
            by=None, reason="blocked by policy", store=store_path,
        )
        cmd_session_deny_approval(args)

        store = SQLiteEvidenceStore(store_path)
        events = store.by_correlation(session_id)
        store.close()
        types = {e["event_type"] for e in events}
        self.assertIn("approval_denied", types)

    def test_grant_approval_cli_outputs_evidence_json(self):
        import argparse
        import json
        from chp_core.cli._session import cmd_session_grant_approval

        store_path, cap_uri, session_id = self._setup_store_with_request()
        args = argparse.Namespace(
            session_id=session_id, capability_uri=cap_uri,
            by="dave", note="approved", store=store_path,
        )
        import io, sys
        captured = io.StringIO()
        sys.stdout = captured
        try:
            cmd_session_grant_approval(args)
        finally:
            sys.stdout = sys.__stdout__
        out = json.loads(captured.getvalue())
        self.assertEqual(out["event_type"], "approval_granted")
        self.assertEqual((out.get("payload") or {}).get("decided_by"), "dave")


if __name__ == "__main__":
    unittest.main()
