# CHP And OpenTelemetry

CHP and OpenTelemetry operate at different layers. OTel is **observability**;
CHP is a **governed, signed evidence plane**. They interoperate — CHP exports
its evidence as OpenTelemetry spans — but CHP is not an OTel trace and does not
concede its own record.

The difference is structural. OpenTelemetry **splits execution across separate,
optional, unsigned signals** — traces, metrics, logs, baggage — none of which
is a contract, none signed, and none carrying governance. CHP unifies **what ran
and what governed it** — policy, risk tier, invariants, safety checks, human
approval, autonomy budgets, and denial — onto **one mandatory, signed,
correlated plane**. A denial, a safety block, or a human approval is a
first-class, tamper-evident event in CHP; in OTel it is, at best, an unsigned
custom attribute on an optional span. That single governed signed plane is what
no observability standard provides.

See the OpenTelemetry traces concept page:
<https://opentelemetry.io/docs/concepts/signals/traces/>.

## Relationship

CHP evidence is capability-boundary truth.

OpenTelemetry traces are operational telemetry.

They overlap when a capability invocation is also represented as a span, but
they answer different questions.

| Question | OpenTelemetry | CHP |
|---|---|---|
| How long did this operation take? | Span duration | Evidence may include duration, but not required in v0.1 |
| What service emitted telemetry? | Resource and service attributes | `host_id` |
| What operation ran? | Span name | `capability_id` and `capability_version` |
| What caused related work? | Trace context and span links | `CorrelationContext` |
| Was execution denied before running? | Usually custom span status/event | First-class `denied` outcome and `execution_denied` evidence |
| Can I replay by capability correlation? | Depends on backend retention/query model | Required local replay by correlation ID |
| What invariants were declared? | Not a core OTel concept | Capability descriptor invariants |

## Export Strategy

Later CHP versions should export evidence to OpenTelemetry:

- one span per capability invocation
- span name: `capability_id`
- attributes:
  - `chp.host_id`
  - `chp.capability_id`
  - `chp.capability_version`
  - `chp.invocation_id`
  - `chp.correlation_id`
  - `chp.outcome`
- span events for CHP evidence events:
  - `execution_started`
  - `execution_completed`
  - `execution_failed`
  - `execution_denied`
  - `execution_skipped`
- span status:
  - OK for `success`
  - ERROR for `failure`
  - UNSET or ERROR for `denied` and `skipped`, depending on exporter policy

## What CHP Preserves Beyond Normal Traces

- capability descriptor identity and version
- explicit invocation envelope
- denial as a protocol outcome
- local replay by correlation ID
- evidence references returned in invocation results
- declared invariants and assurance metadata
- future capability graph construction from evidence

## Non-Goals

CHP v0.1 includes no-dependency mapping helpers in `chp_core.otel`:

- `evidence_to_otel_span(event)`
- `replay_to_otel_spans(events)`

These return OTLP-like dictionaries that preserve CHP fields. They are not a
full OpenTelemetry SDK exporter.

CHP does not replace logs, spans, traces, metrics, baggage, collectors, or
observability backends — it keeps its own governed, signed plane as the source
of truth and **exports to OTel as a bridge** into that ecosystem. Notably, a CHP
export is a span no other source produces: **signed** (carrying `chp.content_hash`)
and **denial-aware** (carrying `chp.denied` / denial code). CHP feeds OTel on
CHP's terms; it does not fold its governed record into OTel's unsigned signals.
