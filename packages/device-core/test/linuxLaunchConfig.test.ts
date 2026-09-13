import { describe, expect, it } from "vitest";
import { serializeLinuxLaunchConfig, writeLinuxLaunchConfig, LinuxLaunchConfigError } from "@domo/device-core";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

describe("LinuxLaunchConfig", () => {
  it("serializes the private bwrap protocol with base64 values", () => {
    const buf = serializeLinuxLaunchConfig({
      workspace: "/tmp/ws",
      cwd: "/tmp/ws",
      argv: ["/tmp/ws/bin", "a", "b"],
      network: false,
      env: { PATH: "/usr/bin", HOME: "/tmp/ws" },
    });
    const text = buf.toString("ascii");
    expect(text.startsWith("PLOW-LATCH-BWRAP-1\n")).toBe(true);
    expect(text).toContain("network 0\n");
    expect(text).toContain(`workspace ${Buffer.from("/tmp/ws").toString("base64")}`);
    expect(text).toContain(`application ${Buffer.from("/tmp/ws/bin").toString("base64")}`);
  });

  it("rejects empty argv and control characters", () => {
    expect(() => serializeLinuxLaunchConfig({
      workspace: "/tmp/ws",
      cwd: "/tmp/ws",
      argv: [],
      network: false,
      env: {},
    })).toThrow(LinuxLaunchConfigError);
    expect(() => serializeLinuxLaunchConfig({
      workspace: "/tmp/ws\n",
      cwd: "/tmp/ws",
      argv: ["/tmp/ws/bin"],
      network: false,
      env: {},
    })).toThrow(LinuxLaunchConfigError);
  });

  it("writes an owner-only config on Linux only", () => {
    if (process.platform !== "linux") {
      expect(() => writeLinuxLaunchConfig(os.tmpdir(), {
        workspace: "/tmp/ws",
        cwd: "/tmp/ws",
        argv: ["/tmp/ws/bin"],
        network: false,
        env: {},
      })).toThrow(/off Linux/);
      return;
    }
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "plow-linux-config-"));
    try {
      const file = writeLinuxLaunchConfig(scratch, {
        workspace: scratch,
        cwd: scratch,
        argv: [path.join(scratch, "bin")],
        network: true,
        env: { HOME: scratch },
      });
      expect(fs.existsSync(file)).toBe(true);
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      fs.rmSync(file, { force: true });
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});
