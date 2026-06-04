"""OTel export demo (v0.2.8).

Shows how to convert CHP evidence events to OTLP spans and either
preview them or send to a collector.

Run (preview only — no collector required):
    python examples/otel-export-demo/demo.py

Run with a real collector (e.g., Jaeger all-in-one):
    python examples/otel-export-demo/demo.py --endpoint http://localhost:4318/v1/traces
"""

import argparse
import json
import tempfile
from pathlib import Path

from chp_core import AgentSession
from chp_core.otel import export_otlp_http, replay_to_otel_spans
from chp_core.store import SQLiteEvidenceStore


def build_demo_session(store_path: str, session_id: str) -> None:
    with AgentSession(store_path=store_path, session_id=session_id) as session:
        session.record_tool(
            "Read",
            {"file_path": "README.md"},
            {"content": "CHP README contents..."},
        )
        session.record_tool(
            "Bash",
            {"command": "git log --oneline -5"},
            {"output": "abc1234 feat: latest\ndef5678 feat: previous\n", "exit_code": 0},
        )
        session.record_tool(
            "Bash",
            {"command": "python -m pytest --tb=short -q"},
            {"output": "5 passed in 0.3s", "exit_code": 0},
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="CHP OTel export demo")
    parser.add_argument("--endpoint", default=None, help="OTLP HTTP endpoint URL")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = str(Path(tmpdir) / "demo.sqlite")
        session_id = "otel-demo-session"

        print("=== Building demo session ===")
        build_demo_session(store_path, session_id)

        store = SQLiteEvidenceStore(store_path)
        events = store.by_correlation(session_id)
        store.close()
        print(f"  Recorded {len(events)} evidence events")

        print("\n=== Converting to OTLP spans ===")
        spans = replay_to_otel_spans(events)
        print(f"  Generated {len(spans)} spans")
        for span in spans:
            status = span.get("status", {}).get("code", "UNSET")
            print(f"    {span['name']:30s}  status={status}  span_id={span['span_id'][:16]}...")

        if args.endpoint:
            print(f"\n=== Exporting to {args.endpoint} ===")
            try:
                result = export_otlp_http(spans, endpoint=args.endpoint)
                print(f"  Exported {result['exported']} spans  HTTP {result['status']}")
            except Exception as exc:  # noqa: BLE001
                print(f"  Export failed: {exc}")
                print("  (Is your OTLP collector running? Try: docker run -p 4318:4318 jaegertracing/all-in-one)")
        else:
            print("\n=== Span preview (use --endpoint URL to send to a collector) ===")
            print(json.dumps(spans, indent=2)[:1000] + "\n  ...")


if __name__ == "__main__":
    main()
