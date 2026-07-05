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
- future assurance and capability graph construction

Logs help, but logs are inconsistent, optional, and usually not a protocol contract.

## The CHP Thesis

At the capability boundary, execution should be observed, **governed**, replayed, and proved — on one record. CHP makes a human approval, an agent's action, and a system call the same *governed, tamper-evident event*: **what ran and what governed it — policy, risk tier, safety checks, human approval, autonomy budgets, denial — emit onto one signed, correlated, replayable plane.**

Governance is present, not future. The policy engine, risk tiers, the safety evaluator, approval workflows, denial-as-evidence, and autonomy budgets are first-class today — signed together with the execution they govern. That single governed, signed plane is the differentiation: observability tools split execution across separate optional unsigned signals and carry no governance; CHP unifies both and proves them.

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

## Launch Positioning

Lead with local visibility:

> See what your agents and tools actually did.

Avoid positioning CHP as a substitute for MCP, tool calling, workflow engines,
or tracing systems. CHP integrates with them by adding capability-level
execution evidence.
