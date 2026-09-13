import { describe, expect, it } from "vitest";
import { HeadlessPolicy, LinuxPresenceGate, PresencePolicy } from "@domo/device-core";
import { makeIntent, type Capability } from "@domo/protocol";

describe("LinuxPresenceGate", () => {
  it("fails closed when the session is locked", async () => {
    const gate = new LinuxPresenceGate(async () => true, "linux", () => true);
    await expect(gate.verify("approval")).resolves.toBe(false);
  });

  it("asks once, then remembers until lock()", async () => {
    let prompts = 0;
    const gate = new LinuxPresenceGate(async () => {
      prompts += 1;
      return true;
    }, "linux", () => false);
    await expect(gate.verify("approval")).resolves.toBe(true);
    await expect(gate.verify("vault")).resolves.toBe(true);
    expect(prompts).toBe(1);
    gate.lock();
    await expect(gate.verify("vault")).resolves.toBe(true);
    expect(prompts).toBe(2);
  });

  it("fails closed when the prompt denies", async () => {
    const gate = new LinuxPresenceGate(async () => false, "linux", () => false);
    await expect(gate.verify("approval")).resolves.toBe(false);
  });

  it("is a no-op on non-Linux platforms", async () => {
    const gate = new LinuxPresenceGate(async () => false, "darwin", () => true);
    await expect(gate.verify("approval")).resolves.toBe(true);
  });

  it("PresencePolicy denies a sensitive allow without presence", async () => {
    const denied = new LinuxPresenceGate(async () => false, "linux", () => false);
    const policy = new PresencePolicy(new HeadlessPolicy({ intent: "allow_once" }), denied);
    const intent = makeIntent({
      agentId: "a",
      agentDisplay: "a",
      deviceId: "d",
      request: "x",
      sessionId: "s",
      capabilities: [{ kind: "process.exec", argv: ["true"] } as Capability],
    });
    await expect(policy.decideIntent(intent)).resolves.toMatchObject({ decision: "deny", source: "presence" });
  });
});
