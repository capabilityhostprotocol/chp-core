# CHP vs MCP

## Short Answer

MCP exposes tools and context to AI applications. CHP governs and evidences execution of capabilities.

They are complementary:

- MCP can be one way an agent discovers and calls tools.
- CHP can wrap those calls so execution emits structured evidence.
- An MCP server can be wrapped as a CHP host.
- A CHP capability can be exposed through an MCP-compatible tool surface.

CHP should not claim to replace MCP.

## MCP Model

The current MCP specification is `2025-11-25` and describes MCP as an open protocol for connecting LLM applications to external data sources and tools using JSON-RPC, stateful connections, and client/server capability negotiation. See the MCP specification overview: <https://modelcontextprotocol.io/specification/>.

MCP server primitives include prompts, resources, and tools. Tools are model-controlled executable functions exposed to the language model. See the MCP server overview and tools spec:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/index>
- <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

Tool discovery uses `tools/list`. Tool invocation uses `tools/call`. A tool definition includes a name, description, input schema, optional output schema, annotations, and execution metadata.

MCP tool errors are split between protocol errors and tool execution errors. Tool execution errors are returned in the tool result with `isError: true`.

## CHP Model

CHP defines a capability boundary. A capability is not only a callable function. It has stable identity, version, modes, invariants, invocation envelope, correlation context, outcome semantics, and evidence emission.

CHP v0.1 requires evidence for:

- started execution
- completed execution
- failed execution
- denied execution, where applicable

CHP does not require a specific transport, model provider, agent loop, or workflow engine.

## Concept Mapping

| MCP Concept | CHP Concept | Notes |
|---|---|---|
| MCP server | Capability host | MCP server is a transport/integration surface. CHP host is any runtime that declares and evidences capabilities. |
| Tool | Capability | A tool can map to a capability, but CHP adds version, invariants, correlation, and evidence requirements. |
| `tools/list` | Discovery | MCP discovery returns model-facing tool definitions. CHP discovery returns execution-facing capability descriptors. |
| `tools/call` | Invocation envelope | MCP invocation names a tool and arguments. CHP invocation carries correlation, subject, mode, metadata, and payload. |
| Tool result | Invocation result | CHP result has explicit `success`, `failure`, `denied`, or `skipped` outcome plus evidence references. |
| `isError` | `failure` outcome | MCP tool execution errors can map to CHP `execution_failed`. |
| JSON-RPC protocol error | Denial or protocol error | Unknown tools can map to CHP `execution_denied` with `capability_not_found`. |
| Tool annotations | Invariants or metadata | MCP says annotations should be treated as untrusted unless from trusted servers. CHP invariants are declared execution constraints. |
| Logs | Evidence events | MCP includes logging as a utility, but CHP evidence is mandatory execution truth at the boundary. |

## Gaps CHP Covers

Evidence:

- MCP does not require every tool attempt to emit structured started/completed/failed/denied evidence.
- CHP makes evidence mandatory.

Correlation:

- MCP JSON-RPC IDs correlate requests and responses.
- CHP correlation IDs reconstruct causal execution across tools, agents, systems, and replay.

Denial semantics:

- MCP has protocol errors and tool execution errors.
- CHP has explicit denial outcomes for boundary decisions before execution.

Replay:

- MCP does not define replay by correlation ID.
- CHP v0.1 requires it.

Invariants:

- MCP tool annotations describe behavior but are not policy.
- CHP declares invariants at the capability boundary.

Assurance:

- MCP does not define evidence assurance levels.
- CHP includes minimal assurance metadata and leaves stronger trust layers for later.

## Where MCP Is Stronger

- Broad and growing AI application ecosystem.
- Model-facing tool discovery.
- Standard client/server lifecycle and transports.
- Prompts, resources, tools, sampling, roots, and elicitation in one integration protocol.
- User consent and UI guidance around model-controlled tools.

## Integration Recommendation

Support an experimental MCP bridge at launch, but keep it separate from the protocol core.

Recommended packages:

- `chp-core`: spec, schemas, local host, conformance, local replay.
- `chp-mcp-bridge`: MCP SDK integration that can wrap MCP tools as CHP capabilities and expose CHP capabilities as MCP tools.

The repository now includes a dependency-light experimental prototype in `examples/mcp-bridge-demo/`.

## Launch Risks

- MCP changes over time. The bridge must track current MCP SDK and protocol revisions independently from CHP core.
- Tool name collisions require deterministic namespacing.
- MCP tool descriptions and annotations are not sufficient trust signals.
- MCP tool results can be unstructured; CHP evidence must stay structured even when tool output is text.
- User consent and confirmation prompts remain the MCP client or host application's responsibility.

## Recommendation

At launch:

- Position CHP as the execution evidence layer for MCP and non-MCP tools.
- Ship the MCP bridge as an experimental prototype or separate package, not as part of the core spec.
- Do not claim MCP equivalence or replacement.
- Demonstrate one MCP-style tool wrapped by CHP evidence.
