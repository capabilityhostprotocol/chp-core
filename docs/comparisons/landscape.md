# CHP Landscape Comparison

CHP is a capability execution evidence layer. It does not replace tool-calling APIs, agent frameworks, workflow engines, observability systems, API gateways, or event streams.

| System | Primary Unit | Solves | Missing vs CHP | Integration Path |
|---|---|---|---|---|
| MCP | Tool, resource, prompt | Standard way for LLM apps to connect to tools and context. | Mandatory execution evidence, denial semantics, replay by correlation ID, invariants, assurance. | Wrap MCP tools as CHP capabilities or expose CHP capabilities as MCP tools. |
| OpenAI tool calling | Function tool call | Model selects functions described by schemas; app executes calls and returns outputs. | Host-level evidence, replay, denial records, capability graph semantics. | Invoke CHP capabilities from the app-side function dispatcher. |
| Anthropic tool use | Client or server tool use block | Claude emits structured tool use; client tools run in the application, server tools run on Anthropic infrastructure. | Capability descriptors, evidence store, correlation replay, invariant model. | Wrap client-side tool execution with CHP. Server-side tools can emit observed trace events when visible. |
| LangChain tools | Callable tool with schema and runtime context | Agent tool abstraction, state access, memory, middleware, streaming. | Protocol-level evidence requirements and conformance. | Register LangChain tools as CHP capabilities or emit CHP evidence from middleware/tool runtime. |
| LlamaIndex tools | Tool or ToolSpec | Agent-facing API-like tools with name, description, function schema. | Evidence semantics, denial, replay, assurance. | Wrap LlamaIndex `Tool` calls through a CHP host. |
| Temporal | Workflow execution and activity | Durable workflow orchestration, replay, retries, long-running execution. | Tool/agent capability boundary protocol and open evidence schema for arbitrary hosts. | Treat Temporal activities or workflow steps as capabilities; emit CHP evidence at activity boundaries. |
| OpenTelemetry | Trace/span/log/metric | Observability signals and distributed tracing — execution split across separate, optional, unsigned signals. | Governance on the same record (denial, risk tier, safety, approval), one signed plane, and integrity — OTel is unsigned and ungoverned. | Export CHP evidence as signed, denial-aware OTel spans (a bridge; CHP keeps its governed plane as source of truth). |
| W3C PROV / OpenLineage | Entity / Activity / Agent | Provenance and lineage — a passive, after-the-fact description of what was used and produced. | Active emission at the boundary, governance/denial semantics, and cryptographic integrity — PROV/OpenLineage lineage is unsigned and history-only. | Express CHP evidence as PROV/OpenLineage; CHP adds the signing + governance those lack (signed, governed provenance). |
| API gateways | Route/service/API request | Traffic management, auth, rate limiting, API publishing, monitoring. | Agent/tool capability semantics and per-capability execution evidence. | A gateway route can invoke a CHP capability or add CHP correlation/evidence at upstream boundaries. |
| Event streaming systems | Event/topic/stream | Durable event transport, pub/sub, stream processing. | Capability declaration and governed invocation boundary. | Publish CHP evidence events to Kafka or similar streams for production fan-out. |

## Grounding Sources

- MCP tools are discovered with `tools/list` and invoked with `tools/call`: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP uses JSON-RPC, stateful connections, and capability negotiation: <https://modelcontextprotocol.io/specification/>
- OpenAI function calling defines tools by schema and requires application-side execution of model tool calls: <https://platform.openai.com/docs/guides/function-calling>
- Anthropic distinguishes client tools run by the application from server tools run by Anthropic infrastructure: <https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview>
- LangChain tools are callable functions with well-defined inputs and outputs passed to chat models: <https://docs.langchain.com/oss/python/langchain/tools>
- LlamaIndex tools are agent-oriented API-like abstractions with metadata and schemas: <https://developers.llamaindex.ai/python/framework/module_guides/deploying/agents/tools/>
- Temporal workflows use event history for replay, and activities are single well-defined actions: <https://docs.temporal.io/workflows> and <https://docs.temporal.io/activities>
- OpenTelemetry traces are built from spans, context propagation, and span events: <https://opentelemetry.io/docs/concepts/signals/traces/>
- Kafka event streaming captures, stores, processes, and routes streams of events: <https://kafka.apache.org/intro/>
- API gateways publish, monitor, secure, and route APIs to upstream services: <https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html> and <https://developer.konghq.com/gateway/entities/service/>

## Practical Positioning

Lead with:

> CHP lets you see what your agents and tools actually did.

Do not lead with:

- replacing MCP
- replacing workflow engines
- enterprise compliance
- universal policy enforcement

CHP's launch wedge is local execution evidence. Production trust can build on that later.
