from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (
    AssuranceMetadata,
    CapabilityDescriptor,
    CorrelationContext,
    DenialReason,
    ExecutionEvidence,
    HostDescriptor,
    InvariantDescriptor,
    InvocationEnvelope,
    LocalCapabilityHost,
    ReplayQuery,
    SQLiteEvidenceStore,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "schemas"


class SchemaValidationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.name: json.loads(path.read_text())
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        }
        resources = [
            (schema["$id"], Resource.from_contents(schema))
            for schema in cls.schemas.values()
        ]
        cls.registry = Registry().with_resources(resources)

    def validate_instance(self, schema_name: str, instance: object) -> None:
        schema = self.schemas[schema_name]
        validator = Draft202012Validator(schema, registry=self.registry)
        validator.validate(instance)

    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        self.assertGreaterEqual(len(self.schemas), 9)
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)

    def test_v01_public_names_and_outcomes_are_frozen(self) -> None:
        self.assertEqual(HostDescriptor.__name__, "HostDescriptor")
        self.assertEqual(ExecutionEvidence.__name__, "ExecutionEvidence")
        self.assertEqual(self.schemas["host-descriptor.schema.json"]["title"], "HostDescriptor")
        self.assertEqual(self.schemas["execution-evidence.schema.json"]["title"], "ExecutionEvidence")
        self.assertEqual(self.schemas["evidence-event.schema.json"]["title"], "ExecutionEvidence")
        self.assertEqual(
            self.schemas["invocation-result.schema.json"]["properties"]["outcome"]["enum"],
            ["success", "failure", "denied", "skipped"],
        )
        self.assertEqual(
            self.schemas["evidence-event.schema.json"]["properties"]["outcome"]["enum"],
            ["success", "failure", "denied", "skipped", None],
        )

    async def test_reference_objects_match_schemas(self) -> None:
        host = LocalCapabilityHost(
            "schema-test-host",
            store=SQLiteEvidenceStore(":memory:"),
        )

        async def echo(_ctx, payload):
            return {"echo": payload["value"]}

        capability = CapabilityDescriptor(
            id="schema.echo",
            version="1.0.0",
            description="Echo a value.",
            invariants=[
                InvariantDescriptor(
                    id="requires_value",
                    kind="required_payload_fields",
                    enforcement="host",
                    parameters={"fields": ["value"]},
                )
            ],
        )
        host.register(capability, echo)

        envelope = InvocationEnvelope(
            capability_id="schema.echo",
            payload={"value": "ok"},
            correlation=CorrelationContext(correlation_id="schema-correlation"),
        )
        result = await host.ainvoke_envelope(envelope)
        evidence = host.replay("schema-correlation")[0]
        replay_result = host.replay_result(ReplayQuery(correlation_id="schema-correlation"))

        self.validate_instance("capability-descriptor.schema.json", capability.to_dict())
        self.validate_instance("host-descriptor.schema.json", host.discover())
        self.validate_instance("invocation-envelope.schema.json", envelope.to_dict())
        self.validate_instance("invocation-result.schema.json", result.to_dict())
        self.validate_instance("evidence-event.schema.json", evidence)
        self.validate_instance("execution-evidence.schema.json", evidence)
        self.validate_instance("replay-query.schema.json", ReplayQuery(correlation_id="schema-correlation").to_dict())
        self.validate_instance("replay-result.schema.json", replay_result.to_dict())
        self.validate_instance(
            "correlation-context.schema.json",
            CorrelationContext(correlation_id="schema-correlation").to_dict(),
        )
        self.validate_instance(
            "denial-reason.schema.json",
            DenialReason(code="unsupported_mode", message="Unsupported mode.", retryable=False).to_dict(),
        )
        self.validate_instance(
            "invariant-descriptor.schema.json",
            capability.invariants[0].to_dict(),
        )
        self.validate_instance(
            "assurance-metadata.schema.json",
            AssuranceMetadata().to_dict(),
        )


if __name__ == "__main__":
    unittest.main()
