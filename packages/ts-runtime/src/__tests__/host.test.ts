import { describe, it, expect, beforeEach } from "vitest";
import { LocalCapabilityHost, SQLiteEvidenceStore } from "../index.js";

describe("LocalCapabilityHost", () => {
  let host: LocalCapabilityHost;

  beforeEach(() => {
    const store = new SQLiteEvidenceStore(":memory:");
    host = new LocalCapabilityHost("test-host", store);
    host.register(
      { id: "test.echo", version: "1.0.0", risk: "low" },
      async (_ctx, payload) => ({ echoed: payload["input"] })
    );
  });

  it("invokes a registered capability", async () => {
    const result = await host.invoke("test.echo", { input: "hello" });
    expect(result.success).toBe(true);
    expect(result.outcome).toBe("success");
    expect(result.data).toEqual({ echoed: "hello" });
  });

  it("returns denied for unknown capability", async () => {
    const result = await host.invoke("test.unknown");
    expect(result.success).toBe(false);
    expect(result.outcome).toBe("denied");
    expect(result.denial?.code).toBe("capability_not_found");
  });

  it("emits evidence events", async () => {
    const result = await host.invoke("test.echo", { input: "hi" }, { correlationId: "corr-123" });
    expect(result.evidence_ids.length).toBeGreaterThanOrEqual(2);
    const events = host.replay("corr-123");
    expect(events.length).toBeGreaterThanOrEqual(2);
    expect(events[0]["event_type"]).toBe("execution_started");
    expect(events[events.length - 1]["event_type"]).toBe("execution_completed");
  });

  it("verifies chain integrity", async () => {
    await host.invoke("test.echo", { input: "a" }, { correlationId: "chain-test" });
    await host.invoke("test.echo", { input: "b" }, { correlationId: "chain-test" });
    const result = host.verifyChain("chain-test");
    expect(result.valid).toBe(true);
    expect(result.event_count).toBeGreaterThanOrEqual(4);
  });

  it("propagates correlation ID", async () => {
    const result = await host.invoke("test.echo", {}, { correlationId: "my-session" });
    expect(result.correlation_id).toBe("my-session");
  });

  it("ctx.emit adds custom evidence events", async () => {
    host.register(
      { id: "test.emitter", version: "1.0.0" },
      async (ctx, _payload) => {
        ctx.emit("custom_event", { note: "hello from capability" });
        return { ok: true };
      }
    );
    const result = await host.invoke("test.emitter", {}, { correlationId: "emit-test" });
    const events = host.replay("emit-test");
    const customEvent = events.find((e) => e["event_type"] === "custom_event");
    expect(customEvent).toBeDefined();
    expect(result.evidence_ids).toContain(customEvent?.["event_id"]);
  });
});

describe("SQLiteEvidenceStore", () => {
  it("counts events by correlation", async () => {
    const store = new SQLiteEvidenceStore(":memory:");
    const host = new LocalCapabilityHost("s", store);
    host.register({ id: "s.noop", version: "1.0.0" }, async () => ({}));
    await host.invoke("s.noop", {}, { correlationId: "c1" });
    await host.invoke("s.noop", {}, { correlationId: "c1" });
    expect(store.countByCorrelation("c1")).toBeGreaterThanOrEqual(4);
  });
});
