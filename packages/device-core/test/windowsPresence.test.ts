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

  it("asks for a PASSWORD, not Hello, when Hello has no hardware to run on", async () => {
    // The two prompts are not interchangeable. `requestConsent` is the Hello
    // face/fingerprint verifier and is unreachable without biometric hardware;
    // `requestPassword` is a credential dialog that LogonUser checks. A
    // PIN-only account therefore gets a password prompt that offers to create
    // one — which is the complaint, pinned here so the branch cannot be
    // "simplified" into claiming it is a Hello prompt.
    let asked: string[] = [];
    const native = hello("device-not-present");
    native.requestConsent = async () => (asked.push("consent"), true);
    native.requestPassword = async () => (asked.push("password"), true);
    await expect(new WindowsPresenceGate(native, "win32").verify("vault")).resolves.toBe(true);
    expect(asked).toEqual(["password"]);
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
