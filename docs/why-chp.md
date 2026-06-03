# Why CHP?

Agent and tool systems can call powerful functions, APIs, runtimes, and business systems. The hard part is often not calling the tool. The hard part is knowing what actually happened after the call boundary was crossed.

CHP focuses on that boundary.

## The Problem

Common tool and agent stacks can answer:

- What tools are available?
- Which schema should the model see?
- How do I call the function?
- How do I return output to the model?

They often do not standardize:

- structured evidence for every execution attempt
- correlation across agents, tools, and systems
- denial records
- replay by causal trace
- capability-level invariants

Logs help, but logs are inconsistent, optional, and usually not a protocol contract.

## The CHP Thesis

Execution should be observable, governable, replayable, and provable at the capability boundary.

v0.1 starts with observable and replayable. Governance comes later.

## What Makes A Capability Different From A Tool?

A tool is usually a callable function exposed to a model or runtime.

A CHP capability is an executable action with:

- stable identity
- version
- declared modes
- declared invariants
- invocation boundary
- correlation
- outcome semantics
- evidence emission

That makes it possible to ask:

- What did this system do?
- Which capability did it invoke?
- Under what correlation?
- Did it start?
- Did it succeed, fail, get denied, or get skipped?
- What evidence supports that answer?
