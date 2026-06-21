"""Simple tool call demo — the minimal CHP pattern.

Run:
    python examples/simple-tool-call/demo.py
"""

import json
from chp_core import LocalCapabilityHost, capability


@capability(
    id="files.word_count",
    version="1.0.0",
    description="Count words in a text string.",
    tags=["text", "analysis"],
)
def word_count(ctx, text: str) -> dict:
    count = len(text.split())
    ctx.emit("word_count_completed", {"word_count": count, "char_count": len(text)})
    return {"word_count": count, "char_count": len(text)}


@capability(
    id="math.add",
    version="1.0.0",
    description="Add two numbers.",
    tags=["math"],
)
def add(ctx, a: float, b: float) -> dict:
    result = a + b
    ctx.emit("add_completed", {"result": result})
    return {"result": result}


host = LocalCapabilityHost(host_id="simple-demo")
host.register(word_count)
host.register(add)

print("=== Registered capabilities ===")
for cap in host.discover()["capabilities"]:
    print(f"  {cap['id']}:{cap['version']}  —  {cap['description']}")

print()

# Invoke a capability
result = host.invoke("files.word_count", {"text": "hello world from CHP"})
print(f"=== Invocation: {result.capability_id} ===")
print(f"  outcome:     {result.outcome}")
print(f"  data:        {result.data}")
print(f"  evidence:    {len(result.evidence_ids)} events emitted")

print()

# Every invocation carries a correlation ID for replay
correlation_id = result.correlation.correlation_id
events = host.replay(correlation_id)
print(f"=== Replay ({correlation_id}) ===")
for event in events:
    print(f"  [{event['event_type']:28s}]  outcome={event.get('outcome') or '-'}")

print()

# Invoke a second capability — share the correlation ID to group them
result2 = host.invoke(
    "math.add",
    {"a": 3, "b": 4},
    correlation_id=correlation_id,
)
print(f"=== Invocation: {result2.capability_id} ===")
print(f"  outcome:  {result2.outcome}")
print(f"  data:     {result2.data}")

events = host.replay(correlation_id)
print(f"\n=== Full replay ({len(events)} events under same correlation ID) ===")
for event in events:
    print(f"  [{event['event_type']:28s}]  cap={event['capability_id']}")
