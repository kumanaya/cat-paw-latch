import { describe, expect, it } from "vitest";
import { HeadlessPolicy, PresencePolicy, WindowsPresenceGate, type NativeHello } from "@domo/device-core";
import { makeIntent, type Capability } from "@domo/protocol";

const hello = (availability: string, answer = true): NativeHello => ({
  checkAvailability: async () => availability,
  requestConsent: async () => answer,
  requestPassword: async () => answer,
});

describe("WindowsPresenceGate", () => {
  it("uses Hello when it is available and forgets it on lock", async () => {
    let calls = 0;
    const native = hello("available");
    native.requestConsent = async () => (++calls, true);
    const gate = new WindowsPresenceGate(native, "win32");
    await expect(gate.verify("vault")).resolves.toBe(true);
    await expect(gate.verify("approval")).resolves.toBe(true);
    expect(calls).toBe(1);
    gate.lock();
    await expect(gate.verify("vault")).resolves.toBe(true);
    expect(calls).toBe(2);
  });

  it("uses the native Windows-password verifier when Hello is unavailable", async () => {
    let password = 0;
    const native = hello("device-not-present");
    native.requestPassword = async () => (++password, true);
    await expect(new WindowsPresenceGate(native, "win32").verify("vault")).resolves.toBe(true);
    expect(password).toBe(1);
  });

  it("fails closed without an adapter or after a cancelled prompt", async () => {
    await expect(new WindowsPresenceGate(null, "win32").verify("vault")).resolves.toBe(false);
    await expect(new WindowsPresenceGate(hello("available", false), "win32").verify("vault")).resolves.toBe(false);
  });

  it("requires presence only after a sensitive approval was allowed", async () => {
    const denied = new WindowsPresenceGate(hello("available", false), "win32");
    const policy = new PresencePolicy(new HeadlessPolicy({ intent: "allow_once" }), denied);
    const intent = makeIntent({ agentId: "a", agentDisplay: "a", deviceId: "d", request: "x", sessionId: "s",
      capabilities: [{ kind: "process.exec", argv: ["cmd"] } as Capability] });
    await expect(policy.decideIntent(intent)).resolves.toMatchObject({ decision: "deny", source: "presence" });
  });
});
